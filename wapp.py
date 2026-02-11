# app.py
# NinjaZight SE - versión robusta + WAF/CDN + WHOIS destacado
# Reqs: streamlit, requests
# Opcionales: dnspython, ipwhois, google-genai (Gemini)
#
# Ejecutar: streamlit run app.py

import streamlit as st
import socket
import ssl
import re
import time
import json
import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# -----------------------------
# Page config
# -----------------------------
st.set_page_config(page_title="NinjaZight SE", layout="wide", page_icon="🥷")


# -----------------------------
# Optional deps (soft-import)
# -----------------------------
DNSPYTHON_OK = False
IPWHOIS_OK = False
try:
    import dns.resolver  # type: ignore
    DNSPYTHON_OK = True
except Exception:
    DNSPYTHON_OK = False

try:
    from ipwhois import IPWhois  # type: ignore
    IPWHOIS_OK = True
except Exception:
    IPWHOIS_OK = False

# Gemini (opcional)
GEMINI_OK = False
CLIENT = None
MODEL_ID = None
try:
    from google import genai  # type: ignore
    GEMINI_OK = True
except Exception:
    GEMINI_OK = False


# -----------------------------
# Constants / Helpers
# -----------------------------
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)

UA_REAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def normalize_target(inp: str) -> str:
    """Accepts domain or URL; returns domain (host) only."""
    s = (inp or "").strip()
    s = s.replace("\u200b", "")  # zero-width cleanup
    s = re.sub(r"^\s+", "", s)
    s = re.sub(r"\s+$", "", s)
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s[:-1] if s.endswith(".") else s
    return s.lower()


def is_valid_domain(dom: str) -> bool:
    if not dom or len(dom) > 253:
        return False
    if dom == "localhost":
        return False
    # Reject raw IP input as "domain"
    try:
        ipaddress.ip_address(dom)
        return False
    except Exception:
        pass
    return bool(DOMAIN_RE.match(dom))


def build_requests_session(total_retries: int = 2, backoff: float = 0.25) -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=total_retries,
        connect=total_retries,
        read=total_retries,
        status=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=24, pool_maxsize=24)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


def safe_get(
    sess: requests.Session,
    url: str,
    timeout: float,
    verify_tls: bool,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    h = {"User-Agent": UA_REAL}
    if headers:
        h.update(headers)
    return sess.get(url, timeout=timeout, verify=verify_tls, headers=h, allow_redirects=True)


def parse_cert_subject(cert: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    subj = cert.get("subject", ())
    for rdn in subj:
        for k, v in rdn:
            out[str(k)] = str(v)
    return out


def asn_norm(s: str) -> str:
    if not s:
        return "N/A"
    m = re.search(r"AS\s*([0-9]+)", s, flags=re.IGNORECASE)
    if m:
        return f"AS{m.group(1)}"
    m2 = re.search(r"\b([0-9]{3,10})\b", s)
    if m2:
        return f"AS{m2.group(1)}"
    return s.strip()[:64]


# -----------------------------
# Data model
# -----------------------------
@dataclass
class InfraData:
    domain: str

    # DNS
    a_records: List[str]
    cname_chain: List[str]
    final_ip: str

    # WHOIS
    whois_owner: str
    whois_cidr: str
    whois_asn: str

    # Ports
    open_ports: List[int]

    # Origin bypass heuristic
    origin_bypass_http: bool
    origin_bypass_https: bool

    # TLS
    tls_cn: str
    tls_san: List[str]
    tls_issuer: str
    tls_not_after: str

    # HTTP headers
    headers: Dict[str, str]
    server_hdr: str

    # Edge/WAF/CDN inference
    cdn_hint: str
    waf_hint: str
    cdn_vendor: str
    waf_vendor: str
    edge_evidence: str

    # Security posture
    sec_headers_ok: bool

    # Misc
    notes: List[str]
    errors: List[str]
    debug: Dict[str, Any]


# -----------------------------
# Gemini boot (optional)
# -----------------------------
@st.cache_resource
def boot_gemini():
    if not GEMINI_OK:
        return None, None, "google-genai not installed"
    try:
        key = st.secrets.get("GEMINI_API_KEY", None)
        if not key:
            return None, None, "Missing GEMINI_API_KEY in secrets"
        client = genai.Client(api_key=key)
        return client, "gemini-2.0-flash", ""
    except Exception as e:
        return None, None, f"Gemini init error: {e!r}"


CLIENT, MODEL_ID, GEMINI_BOOT_ERR = boot_gemini()


# -----------------------------
# DNS resolution
# -----------------------------
def resolve_dns(domain: str, timeout: float = 3.0) -> Tuple[List[str], List[str], List[str]]:
    """
    Returns: (A_records, cname_chain, errors)
    """
    errors: List[str] = []
    a_records: List[str] = []
    cname_chain: List[str] = []

    if DNSPYTHON_OK:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout

            # CNAME chain (best effort)
            cur = domain
            for _ in range(10):
                try:
                    ans = resolver.resolve(cur, "CNAME")
                    nxt = str(ans[0].target).rstrip(".")
                    cname_chain.append(nxt)
                    cur = nxt
                except Exception:
                    break

            # A records from final name (or domain)
            qname = cname_chain[-1] if cname_chain else domain
            ans_a = resolver.resolve(qname, "A")
            for r in ans_a:
                ip = str(r)
                try:
                    ipaddress.ip_address(ip)
                    a_records.append(ip)
                except Exception:
                    pass

        except Exception as e:
            errors.append(f"DNS error (dnspython): {e!r}")

    if not a_records:
        # Fallback
        try:
            infos = socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
            for info in infos:
                ip = info[4][0]
                try:
                    ipaddress.ip_address(ip)
                    if ip not in a_records:
                        a_records.append(ip)
                except Exception:
                    pass
        except Exception as e:
            errors.append(f"DNS error (socket): {e!r}")

    return a_records, cname_chain, errors


# -----------------------------
# WHOIS/IP ownership
# -----------------------------
def ip_whois(ip: str) -> Tuple[str, str, str, str]:
    """
    Returns: (owner, cidr, asn, raw_json_string)
    """
    owner = "N/A"
    cidr = "N/A"
    asn = "N/A"
    raw = ""

    if not ip or ip == "N/A":
        return owner, cidr, asn, raw

    if IPWHOIS_OK:
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            raw = json.dumps(rdap, ensure_ascii=False)[:20000]

            asn = asn_norm(str(rdap.get("asn", "") or ""))
            cidr = str(rdap.get("asn_cidr", "") or "") or "N/A"

            net = rdap.get("network", {}) or {}
            name = net.get("name") or net.get("handle") or ""
            owner = str(name)[:128] if name else "N/A"

            return owner or "N/A", cidr or "N/A", asn or "N/A", raw
        except Exception as e:
            raw = f"ipwhois error: {e!r}"
            return owner, cidr, asn, raw

    return owner, cidr, asn, raw


# -----------------------------
# Port scan (concurrent)
# -----------------------------
def scan_ports(host: str, ports: List[int], timeout: float = 0.6, max_workers: int = 64) -> List[int]:
    import concurrent.futures

    open_ports: List[int] = []

    def check(p: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                r = s.connect_ex((host, p))
                return p if r == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(check, p) for p in ports]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r is not None:
                open_ports.append(r)

    return sorted(open_ports)


# -----------------------------
# TLS details
# -----------------------------
def tls_details(domain: str, timeout: float = 5.0) -> Tuple[str, List[str], str, str, List[str]]:
    """
    Returns: (cn, san_list, issuer_common_name, not_after, errors)
    """
    errors: List[str] = []
    cn = "N/A"
    san: List[str] = []
    issuer = "N/A"
    not_after = "N/A"

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subj = parse_cert_subject(cert)
        cn = subj.get("commonName", "N/A")

        san_tuples = cert.get("subjectAltName", ()) or ()
        for t in san_tuples:
            if len(t) == 2 and t[0].lower() == "dns":
                san.append(str(t[1]))

        issuer_t = cert.get("issuer", ()) or ()
        issuer_dict: Dict[str, str] = {}
        for rdn in issuer_t:
            for k, v in rdn:
                issuer_dict[str(k)] = str(v)
        issuer = issuer_dict.get("commonName", "N/A")

        not_after = str(cert.get("notAfter", "N/A"))
    except Exception as e:
        errors.append(f"TLS error: {e!r}")

    return cn, san[:50], issuer, not_after, errors


# -----------------------------
# Origin bypass checks
# -----------------------------
def origin_bypass_checks(
    sess: requests.Session,
    domain: str,
    ip: str,
    timeout: float,
) -> Tuple[bool, bool, List[str]]:
    """
    Heuristic check:
    - HTTP to IP with Host header = domain
    - HTTPS to IP with Host header = domain (verify disabled)
    Returns: (http_bypass, https_bypass, errors)
    """
    errors: List[str] = []
    http_ok = False
    https_ok = False

    if not ip or ip == "N/A":
        return False, False, errors

    # HTTP
    try:
        r = safe_get(sess, f"http://{ip}/", timeout=timeout, verify_tls=False, headers={"Host": domain})
        if r is not None and 200 <= r.status_code < 400:
            body = (r.text or "")[:4000].lower()
            if domain.lower() in body or len(body) > 200:
                http_ok = True
    except Exception as e:
        errors.append(f"Origin HTTP bypass check error: {e!r}")

    # HTTPS (verify disabled)
    try:
        r2 = safe_get(sess, f"https://{ip}/", timeout=timeout, verify_tls=False, headers={"Host": domain})
        if r2 is not None and 200 <= r2.status_code < 400:
            body2 = (r2.text or "")[:4000].lower()
            if domain.lower() in body2 or len(body2) > 200:
                https_ok = True
    except Exception as e:
        errors.append(f"Origin HTTPS bypass check error: {e!r}")

    return http_ok, https_ok, errors


# -----------------------------
# Header analysis / hints
# -----------------------------
def analyze_headers(headers: Dict[str, str]) -> Tuple[str, str, bool, str]:
    """
    Returns: (server, cdn_hint, sec_headers_ok, waf_hint)
    """
    hl = {k.lower(): v for k, v in (headers or {}).items()}

    server = (hl.get("server", "N/A") or "N/A")[:80]

    cdn_hint = "N/A"
    for k in ["cf-ray", "cf-cache-status", "x-akamai-transformed", "x-akamai-request-id", "x-cache", "via", "x-cdn"]:
        if k in hl:
            cdn_hint = f"{k}: {str(hl.get(k,''))[:80]}"
            break

    waf_hint = "N/A"
    blob = (str(hl.get("server", "")) + " " + str(hl.get("via", "")) + " " + str(hl.get("x-cache", ""))).lower()
    if "akamai" in blob:
        waf_hint = "Posible Akamai (headers/via)"
    elif "cloudflare" in blob or "cf-ray" in hl:
        waf_hint = "Posible Cloudflare"
    elif "imperva" in (str(hl.get("server", "")) + " " + str(hl.get("x-iinfo", ""))).lower():
        waf_hint = "Posible Imperva"
    elif "x-sucuri-id" in hl or "sucuri" in str(hl.get("server", "")).lower():
        waf_hint = "Posible Sucuri"

    sec_headers_ok = ("strict-transport-security" in hl) and ("content-security-policy" in hl)
    return server, cdn_hint, sec_headers_ok, waf_hint


def detect_edge_vendor(domain: str, headers: Dict[str, str], cname_chain: List[str]) -> Tuple[str, str, str]:
    """
    Returns: (cdn_vendor, waf_vendor, evidence)
    Heurístico por señales: headers + CNAME chain.
    """
    hl = {k.lower(): str(v) for k, v in (headers or {}).items()}
    cnames = " ".join([c.lower() for c in (cname_chain or [])])

    evidence: List[str] = []
    cdn = "N/A"
    waf = "N/A"

    # Akamai
    akamai_signals: List[str] = []
    for k in [
        "x-akamai-request-id",
        "x-akamai-session-info",
        "x-akamai-transformed",
        "akamai-cache-status",
        "x-check-cacheable",
        "x-cache",
    ]:
        if k in hl:
            akamai_signals.append(k)
    if "akamai" in hl.get("server", "").lower() or "akamai" in hl.get("via", "").lower():
        akamai_signals.append("server/via contains akamai")
    if any(x in cnames for x in ["akamai", "edgesuite", "edgekey", "akamaiedge", "akadns", "akamaitechnologies"]):
        akamai_signals.append("cname contains akamai pattern")

    if akamai_signals:
        cdn = "Akamai (probable)"
        waf = "Akamai (possible WAAP)"
        evidence += [f"akamai:{s}" for s in akamai_signals]

    # Cloudflare
    cf_signals: List[str] = []
    for k in ["cf-ray", "cf-cache-status", "cf-request-id"]:
        if k in hl:
            cf_signals.append(k)
    if "cloudflare" in hl.get("server", "").lower() or "cloudflare" in cnames:
        cf_signals.append("server/cname contains cloudflare")
    if cf_signals:
        cdn = "Cloudflare (probable)"
        waf = "Cloudflare WAF (probable)"
        evidence += [f"cf:{s}" for s in cf_signals]

    # Fastly
    fastly_signals: List[str] = []
    if "fastly" in hl.get("via", "").lower() or "fastly" in hl.get("x-served-by", "").lower():
        fastly_signals.append("via/x-served-by fastly")
    if "fastly" in cnames:
        fastly_signals.append("cname contains fastly")
    if fastly_signals:
        cdn = "Fastly (probable)"
        evidence += [f"fastly:{s}" for s in fastly_signals]

    # Imperva
    imp_signals: List[str] = []
    if "x-iinfo" in hl:
        imp_signals.append("x-iinfo")
    if "imperva" in hl.get("server", "").lower() or "incapsula" in cnames:
        imp_signals.append("server/cname imperva/incapsula")
    if imp_signals:
        waf = "Imperva (probable)"
        evidence += [f"imperva:{s}" for s in imp_signals]

    # Sucuri
    if "x-sucuri-id" in hl or "sucuri" in hl.get("server", "").lower():
        waf = "Sucuri (probable)"
        evidence.append("sucuri header/server")

    ev = " | ".join(evidence)[:260] if evidence else "N/A"
    return cdn, waf, ev


# -----------------------------
# Gemini analysis (optional)
# -----------------------------
def gemini_analyze(domain: str, infra: InfraData) -> str:
    if CLIENT is None or MODEL_ID is None:
        return "Gemini no disponible (sin API key o init falló)."

    prompt = f"""
Rol: Senior Solutions Engineer (Akamai).
Objetivo: análisis técnico SOLO con datos provistos. Si falta evidencia, indicarlo como 'No concluyente'.

Dominio: {domain}

Datos observados:
- DNS A: {infra.a_records}
- CNAME chain: {infra.cname_chain}
- IP final: {infra.final_ip}
- WHOIS owner: {infra.whois_owner}
- WHOIS ASN: {infra.whois_asn}
- WHOIS CIDR: {infra.whois_cidr}
- Puertos abiertos (connect-scan al dominio): {infra.open_ports}
- TLS CN: {infra.tls_cn}
- TLS SAN (top): {infra.tls_san[:10]}
- TLS Issuer: {infra.tls_issuer}
- TLS NotAfter: {infra.tls_not_after}
- Headers:
  Server: {infra.server_hdr}
  CDN hint: {infra.cdn_hint}
  WAF hint: {infra.waf_hint}
  CDN vendor: {infra.cdn_vendor}
  WAF vendor: {infra.waf_vendor}
  Edge evidence: {infra.edge_evidence}
  Security headers OK (HSTS+CSP): {infra.sec_headers_ok}
- Origin bypass (heurístico por IP + Host header): HTTP={infra.origin_bypass_http}, HTTPS={infra.origin_bypass_https}

Salida requerida:
- 5 bullets, cada uno con: (Observación) -> (Riesgo) -> (Acción recomendada)
- No inventar vendors/tecnologías si no están en headers/DNS.
"""
    try:
        res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
        txt = getattr(res, "text", None)
        if txt:
            return txt.strip()
        return str(res)[:3000]
    except Exception as e:
        return f"Gemini error: {e!r}"


# -----------------------------
# Main infra collection
# -----------------------------
@st.cache_data(show_spinner=False, ttl=600)
def get_infra_data(domain: str, verify_tls: bool) -> InfraData:
    t0 = time.time()
    errors: List[str] = []
    notes: List[str] = []
    debug: Dict[str, Any] = {"timing": {}, "verify_tls": verify_tls}

    # DNS
    a_records, cname_chain, dns_errs = resolve_dns(domain, timeout=3.0)
    errors.extend(dns_errs)
    final_ip = a_records[-1] if a_records else "N/A"

    # WHOIS
    owner, cidr, asn, whois_raw = ip_whois(final_ip)
    if whois_raw:
        debug["whois_raw"] = whois_raw

    # Ports
    common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8008, 8888, 9200, 5601, 2082, 2083, 2086, 2087]
    open_ports = scan_ports(domain, common_ports, timeout=0.6, max_workers=64)

    # TLS
    tls_cn, tls_san, tls_issuer, tls_not_after, tls_errs = tls_details(domain, timeout=5.0)
    errors.extend(tls_errs)

    # HTTP fetch
    sess = build_requests_session(total_retries=2, backoff=0.25)
    headers: Dict[str, str] = {}
    server_hdr = "N/A"
    cdn_hint = "N/A"
    waf_hint = "N/A"
    sec_headers_ok = False

    try:
        r = safe_get(sess, f"https://{domain}/", timeout=7.0, verify_tls=verify_tls)
        headers = dict(r.headers) if r is not None else {}
        server_hdr, cdn_hint, sec_headers_ok, waf_hint = analyze_headers(headers)
        debug["http_status"] = getattr(r, "status_code", None)
        debug["final_url"] = getattr(r, "url", None)
    except requests.exceptions.SSLError as e:
        errors.append(f"HTTPS fetch SSL error: {e!r}")
        try:
            r = safe_get(sess, f"http://{domain}/", timeout=7.0, verify_tls=False)
            headers = dict(r.headers) if r is not None else {}
            server_hdr, cdn_hint, sec_headers_ok, waf_hint = analyze_headers(headers)
            debug["http_status"] = getattr(r, "status_code", None)
            debug["final_url"] = getattr(r, "url", None)
            notes.append("Fallo TLS en fetch HTTPS; se usó fallback HTTP para cabeceras.")
        except Exception as e2:
            errors.append(f"HTTP fetch fallback error: {e2!r}")
    except Exception as e:
        errors.append(f"HTTPS fetch error: {e!r}")

    # Vendor inference (CDN/WAF)
    cdn_vendor, waf_vendor, edge_evidence = detect_edge_vendor(domain, headers, cname_chain)

    # Origin bypass heuristic
    origin_http_bypass, origin_https_bypass, bypass_errs = origin_bypass_checks(
        sess=sess,
        domain=domain,
        ip=final_ip,
        timeout=4.0,
    )
    errors.extend(bypass_errs)

    if origin_http_bypass or origin_https_bypass:
        notes.append("Bypass heurístico: respuesta válida desde IP con Host header. Confirmar comparando contenido/headers vs edge.")
    if final_ip == "N/A":
        notes.append("Sin A record resoluble: input inválido, DNS roto, o resolución bloqueada.")

    debug["timing"]["total_s"] = round(time.time() - t0, 3)

    return InfraData(
        domain=domain,
        a_records=a_records,
        cname_chain=cname_chain,
        final_ip=final_ip,
        whois_owner=owner,
        whois_cidr=cidr,
        whois_asn=asn,
        open_ports=open_ports,
        origin_bypass_http=origin_http_bypass,
        origin_bypass_https=origin_https_bypass,
        tls_cn=tls_cn,
        tls_san=tls_san,
        tls_issuer=tls_issuer,
        tls_not_after=tls_not_after,
        headers={k: str(v) for k, v in headers.items()},
        server_hdr=server_hdr,
        cdn_hint=cdn_hint,
        waf_hint=waf_hint,
        cdn_vendor=cdn_vendor,
        waf_vendor=waf_vendor,
        edge_evidence=edge_evidence,
        sec_headers_ok=sec_headers_ok,
        notes=notes,
        errors=errors,
        debug=debug,
    )


# -----------------------------
# UI
# -----------------------------
st.title("🥷 NinjaZight SE")

with st.sidebar:
    st.subheader("Opciones")
    verify_tls = st.toggle(
        "Verificar TLS (recomendado)",
        value=True,
        help="Si el sitio tiene cert inválido, desactiva para continuar con evidencia parcial.",
    )
    show_debug = st.toggle("Mostrar debug", value=False)
    st.caption("CDN/WAF es inferencia por señales. Bypass origin es heurístico; confirmar siempre.")

target = st.text_input("Dominio o URL:", placeholder="empresa.com / https://empresa.com", label_visibility="collapsed")

run = st.button("🚀 Iniciar Auditoría Ninja", type="primary")

if run:
    dom = normalize_target(target)

    if not is_valid_domain(dom):
        st.error("Input inválido. Esperado: dominio FQDN tipo 'empresa.com'.")
        st.stop()

    with st.status("Analizando infraestructura...", expanded=False) as status:
        infra = get_infra_data(dom, verify_tls=verify_tls)
        status.update(label="Análisis de infraestructura completo", state="complete")

    # --- DASHBOARD METRICS ---
    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "IP final (A)",
        infra.final_ip,
        f"{infra.whois_owner[:20]} {infra.whois_asn}" if (infra.whois_owner != "N/A" or infra.whois_asn != "N/A") else None,
    )

    c2.metric("TLS CN", (infra.tls_cn or "N/A")[:28], (infra.tls_not_after or "N/A")[:28])

    bypass_state = "VULNERABLE" if (infra.origin_bypass_http or infra.origin_bypass_https) else "Protegido"
    c3.metric("Bypass origin", bypass_state, delta="- Riesgo Alto" if bypass_state == "VULNERABLE" else None, delta_color="inverse")

    whois_delta = infra.whois_cidr if infra.whois_cidr != "N/A" else None
    c4.metric("WHOIS (ASN)", infra.whois_asn, whois_delta)

    c1b, c2b, c3b, c4b = st.columns(4)
    c1b.metric("Server header", (infra.server_hdr or "N/A")[:28])
    c2b.metric("CDN", infra.cdn_vendor, (infra.cdn_hint or "N/A")[:36])
    c3b.metric("WAF", infra.waf_vendor, (infra.waf_hint or "N/A")[:36])
    c4b.metric("Security (HSTS+CSP)", "✅ OK" if infra.sec_headers_ok else "❌ Missing")

    st.divider()

    tab_brief, tab_tech = st.tabs(["⚡ Briefing", "🛠️ Técnico"])

    with tab_brief:
        if CLIENT is not None and MODEL_ID is not None:
            with st.spinner("Generando briefing con Gemini..."):
                txt = gemini_analyze(dom, infra)
            st.info(txt)
        else:
            st.warning(f"Gemini no disponible. {GEMINI_BOOT_ERR}".strip())
            bullets = []
            if infra.origin_bypass_http or infra.origin_bypass_https:
                bullets.append("Origin bypass (heurístico) -> posible exposición de origen -> bloquear acceso directo a origen (ACL, mTLS, allowlist edges, WAF en origen).")
            if not infra.sec_headers_ok:
                bullets.append("Faltan HSTS/CSP -> hardening insuficiente -> definir HSTS + CSP estricta por app.")
            if any(p in infra.open_ports for p in [8080, 8443, 3000, 5000, 8000, 8888, 9200, 5601]):
                bullets.append(f"Puertos no estándar abiertos {infra.open_ports} -> superficie extra -> restringir por VPN/allowlist y cerrar en firewall.")
            if infra.tls_not_after != "N/A":
                bullets.append("TLS detectado -> revisar caducidad/cadena -> automatizar renovación + monitoreo.")
            if infra.cdn_vendor != "N/A" or infra.waf_vendor != "N/A":
                bullets.append(f"Edge detectado -> {infra.cdn_vendor}/{infra.waf_vendor} (probable) -> validar con DNS CNAME + headers + logs de edge.")
            if not bullets:
                bullets.append("Evidencia insuficiente para anomalías concluyentes con esta sonda -> ampliar con fingerprinting activo autorizado.")
            st.info("\n".join([f"- {b}" for b in bullets[:5]]))

        if infra.notes:
            st.caption("Notas")
            st.write("\n".join([f"- {n}" for n in infra.notes]))

        if infra.errors:
            st.caption("Errores")
            st.write("\n".join([f"- {e}" for e in infra.errors[:15]]))

    with tab_tech:
        st.write(f"**CNAME chain:** `{infra.cname_chain}`")
        st.write(f"**A records:** `{infra.a_records}`")
        st.write(f"**Puertos abiertos:** `{infra.open_ports}`")

        st.write("**Resumen estructurado:**")
        st.json(
            {
                "domain": infra.domain,
                "dns": {"a": infra.a_records, "cname_chain": infra.cname_chain, "final_ip": infra.final_ip},
                "whois": {"owner": infra.whois_owner, "asn": infra.whois_asn, "cidr": infra.whois_cidr},
                "tls": {"cn": infra.tls_cn, "san": infra.tls_san[:25], "issuer": infra.tls_issuer, "not_after": infra.tls_not_after},
                "http": {
                    "server": infra.server_hdr,
                    "cdn_hint": infra.cdn_hint,
                    "waf_hint": infra.waf_hint,
                    "cdn_vendor": infra.cdn_vendor,
                    "waf_vendor": infra.waf_vendor,
                    "edge_evidence": infra.edge_evidence,
                    "sec_headers_ok": infra.sec_headers_ok,
                },
                "bypass": {"http": infra.origin_bypass_http, "https": infra.origin_bypass_https},
            }
        )

        with st.expander("Evidencia Edge (CDN/WAF)"):
            st.code(infra.edge_evidence or "N/A")

        with st.expander("Headers crudos"):
            st.code("\n".join([f"{k}: {v}" for k, v in infra.headers.items()]) or "N/A")

        # WHOIS raw (solo si ipwhois disponible y hay data)
        if show_debug:
            with st.expander("Debug"):
                st.json(infra.debug)
