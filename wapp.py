# app.py
# NinjaZight SE - robusto + WHOIS consistente + detección WAF/CDN “agresiva”
#
# Cambios clave vs tu versión:
# - WHOIS: si ipwhois no está instalado o falla, cae a `whois` (subprocess) y PARSEA NetName/Org/CIDR/OriginAS.
# - WAF/CDN: combina señales de headers + DNS CNAME + herramientas opcionales (wafw00f/whatweb).
# - Salidas: si no hay evidencia -> "No detectado" (no "N/A").
#
# Reqs: streamlit, requests
# Opcionales: dnspython, ipwhois, google-genai, wafw00f (binario), whatweb (binario)
#
# Ejecutar: streamlit run app.py

import streamlit as st
import socket
import ssl
import re
import time
import json
import ipaddress
import subprocess
import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -----------------------------
# Page config
# -----------------------------
st.set_page_config(page_title="NinjaZight SE", layout="wide", page_icon="🥷")

UNKNOWN = "No detectado"
UA_REAL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

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
# Helpers
# -----------------------------
def normalize_target(inp: str) -> str:
    s = (inp or "").strip()
    s = s.replace("\u200b", "")
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s[:-1] if s.endswith(".") else s
    return s.lower()


def is_valid_domain(dom: str) -> bool:
    if not dom or len(dom) > 253:
        return False
    if dom == "localhost":
        return False
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
        return UNKNOWN
    m = re.search(r"AS\s*([0-9]+)", s, flags=re.IGNORECASE)
    if m:
        return f"AS{m.group(1)}"
    m2 = re.search(r"\b([0-9]{3,10})\b", s)
    if m2:
        return f"AS{m2.group(1)}"
    return s.strip()[:64]


def which(cmd: str) -> Optional[str]:
    p = shutil.which(cmd)
    return p


def run_cmd(args: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return 999, "", f"{e!r}"


def first_nonempty(*vals: str) -> str:
    for v in vals:
        if v and v.strip() and v.strip() != "N/A":
            return v.strip()
    return UNKNOWN


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
    whois_netname: str
    whois_raw: str

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
    cdn_vendor: str
    waf_vendor: str
    edge_evidence: str

    # Tools output (optional)
    wafw00f_summary: str
    whatweb_summary: str

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
    errors: List[str] = []
    a_records: List[str] = []
    cname_chain: List[str] = []

    if DNSPYTHON_OK:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout

            cur = domain
            for _ in range(10):
                try:
                    ans = resolver.resolve(cur, "CNAME")
                    nxt = str(ans[0].target).rstrip(".")
                    cname_chain.append(nxt)
                    cur = nxt
                except Exception:
                    break

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
# WHOIS robust (ipwhois + fallback to whois cmd)
# -----------------------------
def parse_whois_text(raw: str) -> Tuple[str, str, str, str]:
    """
    Returns: (owner, cidr, asn, netname)
    Works with ARIN-style output (NetRange/CIDR/NetName/Organization/OrgName/OriginAS)
    """
    owner = ""
    cidr = ""
    asn = ""
    netname = ""

    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()

        if k in ["orgname", "organization", "org-name", "owner", "custname"]:
            if not owner:
                owner = v
        if k == "netname" and not netname:
            netname = v
        if k == "cidr" and not cidr:
            cidr = v
        if k in ["originas", "origin", "aut-num"]:
            if not asn and v:
                asn = v

    return (
        first_nonempty(owner),
        first_nonempty(cidr),
        asn_norm(asn) if asn else UNKNOWN,
        first_nonempty(netname),
    )


def ip_whois(ip: str) -> Tuple[str, str, str, str, str]:
    """
    Returns: (owner, cidr, asn, netname, raw)
    """
    if not ip or ip == UNKNOWN or ip == "N/A":
        return UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, ""

    # 1) ipwhois (RDAP)
    if IPWHOIS_OK:
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            raw = json.dumps(rdap, ensure_ascii=False)[:20000]

            asn = asn_norm(str(rdap.get("asn", "") or ""))
            cidr = str(rdap.get("asn_cidr", "") or "") or UNKNOWN

            net = rdap.get("network", {}) or {}
            netname = str(net.get("name") or net.get("handle") or "") or UNKNOWN

            # Owner: a veces viene mejor en entities; si no, net.name
            owner = netname
            return first_nonempty(owner), first_nonempty(cidr), asn, first_nonempty(netname), raw
        except Exception:
            pass

    # 2) fallback a `whois` del sistema (tu caso)
    if which("whois"):
        rc, out, err = run_cmd(["whois", ip], timeout=10)
        raw = (out or "") + ("\n" + err if err else "")
        if out.strip():
            owner, cidr, asn, netname = parse_whois_text(out)
            return owner, cidr, asn, netname, raw[:40000]
        return UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, raw[:40000]

    return UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, ""


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
    errors: List[str] = []
    cn = UNKNOWN
    san: List[str] = []
    issuer = UNKNOWN
    not_after = UNKNOWN

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subj = parse_cert_subject(cert)
        cn = subj.get("commonName", UNKNOWN)

        san_tuples = cert.get("subjectAltName", ()) or ()
        for t in san_tuples:
            if len(t) == 2 and t[0].lower() == "dns":
                san.append(str(t[1]))

        issuer_t = cert.get("issuer", ()) or ()
        issuer_dict: Dict[str, str] = {}
        for rdn in issuer_t:
            for k, v in rdn:
                issuer_dict[str(k)] = str(v)
        issuer = issuer_dict.get("commonName", UNKNOWN)

        not_after = str(cert.get("notAfter", UNKNOWN))
    except Exception as e:
        errors.append(f"TLS error: {e!r}")

    return cn, san[:50], issuer, not_after, errors


# -----------------------------
# Origin bypass checks (heurístico)
# -----------------------------
def origin_bypass_checks(sess: requests.Session, domain: str, ip: str, timeout: float) -> Tuple[bool, bool, List[str]]:
    errors: List[str] = []
    http_ok = False
    https_ok = False

    if not ip or ip in [UNKNOWN, "N/A"]:
        return False, False, errors

    try:
        r = safe_get(sess, f"http://{ip}/", timeout=timeout, verify_tls=False, headers={"Host": domain})
        if r is not None and 200 <= r.status_code < 400:
            body = (r.text or "")[:4000].lower()
            if domain.lower() in body or len(body) > 200:
                http_ok = True
    except Exception as e:
        errors.append(f"Origin HTTP bypass check error: {e!r}")

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
# Header aggregation + detection
# -----------------------------
def collect_headers_multi(sess: requests.Session, domain: str, verify_tls: bool) -> Tuple[Dict[str, str], List[str], Dict[str, Any]]:
    """
    Hace varias requests (HEAD/GET) en endpoints típicos para mejorar señales de CDN/WAF.
    Retorna: merged_headers, errors, debug
    """
    errs: List[str] = []
    dbg: Dict[str, Any] = {"probes": []}
    merged: Dict[str, str] = {}

    probes = [
        ("HEAD", f"https://{domain}/"),
        ("GET",  f"https://{domain}/"),
        ("GET",  f"https://{domain}/robots.txt"),
        ("HEAD", f"http://{domain}/"),
        ("GET",  f"http://{domain}/"),
    ]

    for method, url in probes:
        try:
            if method == "HEAD":
                r = sess.head(url, timeout=6.5, verify=verify_tls if url.startswith("https://") else False,
                             headers={"User-Agent": UA_REAL}, allow_redirects=True)
            else:
                r = safe_get(sess, url, timeout=6.5, verify_tls=verify_tls if url.startswith("https://") else False)

            dbg["probes"].append({"url": url, "status": getattr(r, "status_code", None), "final_url": getattr(r, "url", None)})
            # Merge headers: preserva el primero que aparezca (más "edge-ish") y completa faltantes
            for k, v in dict(r.headers).items():
                if k not in merged:
                    merged[k] = str(v)
        except requests.exceptions.SSLError as e:
            errs.append(f"SSL error {url}: {e!r}")
            dbg["probes"].append({"url": url, "ssl_error": True})
        except Exception as e:
            errs.append(f"Fetch error {url}: {e!r}")
            dbg["probes"].append({"url": url, "error": True})

    return merged, errs, dbg


def analyze_headers(headers: Dict[str, str]) -> Tuple[str, bool]:
    hl = {k.lower(): str(v) for k, v in (headers or {}).items()}
    server = (hl.get("server") or UNKNOWN)[:80]
    sec_headers_ok = ("strict-transport-security" in hl) and ("content-security-policy" in hl)
    return server, sec_headers_ok


def detect_edge_vendor(domain: str, headers: Dict[str, str], cname_chain: List[str], extra_signals: List[str]) -> Tuple[str, str, str]:
    """
    Returns: (cdn_vendor, waf_vendor, evidence)
    Heurístico por señales: headers + CNAME chain + tools output (extra_signals).
    Si no hay evidencia -> "No detectado".
    """
    hl = {k.lower(): str(v) for k, v in (headers or {}).items()}
    cnames = " ".join([c.lower() for c in (cname_chain or [])])

    evidence: List[str] = []
    if extra_signals:
        evidence.extend([f"tool:{s}" for s in extra_signals if s])

    cdn = UNKNOWN
    waf = UNKNOWN

    def add_ev(tag: str, items: List[str]):
        for it in items:
            evidence.append(f"{tag}:{it}")

    # Akamai
    akamai = []
    for k in ["x-akamai-request-id", "x-akamai-session-info", "x-akamai-transformed", "akamai-cache-status", "x-check-cacheable", "x-cache"]:
        if k in hl:
            akamai.append(k)
    if "akamai" in (hl.get("via", "") + " " + hl.get("server", "")).lower():
        akamai.append("server/via contains akamai")
    if any(x in cnames for x in ["akamai", "edgesuite", "edgekey", "akamaiedge", "akadns", "akamaitechnologies"]):
        akamai.append("cname akamai pattern")
    if akamai:
        cdn = "Akamai (probable)"
        waf = "Akamai (possible WAAP)"
        add_ev("akamai", akamai)

    # Cloudflare
    cf = []
    for k in ["cf-ray", "cf-cache-status", "cf-request-id", "nel", "report-to"]:
        if k in hl:
            cf.append(k)
    if "cloudflare" in (hl.get("server", "") + " " + cnames).lower():
        cf.append("server/cname contains cloudflare")
    if cf and cdn == UNKNOWN:
        cdn = "Cloudflare (probable)"
        waf = "Cloudflare WAF (probable)"
        add_ev("cf", cf)

    # Fastly
    fastly = []
    for k in ["x-served-by", "x-cache-hits", "x-timer"]:
        if k in hl:
            fastly.append(k)
    if "fastly" in (hl.get("via", "") + " " + cnames).lower():
        fastly.append("via/cname contains fastly")
    if fastly and cdn == UNKNOWN:
        cdn = "Fastly (probable)"
        add_ev("fastly", fastly)

    # Imperva
    imperva = []
    if "x-iinfo" in hl:
        imperva.append("x-iinfo")
    if any(x in cnames for x in ["incapsula", "imperva"]):
        imperva.append("cname incapsula/imperva")
    if imperva and waf == UNKNOWN:
        waf = "Imperva (probable)"
        add_ev("imperva", imperva)

    # Sucuri
    sucuri = []
    if "x-sucuri-id" in hl:
        sucuri.append("x-sucuri-id")
    if "sucuri" in hl.get("server", "").lower():
        sucuri.append("server contains sucuri")
    if sucuri and waf == UNKNOWN:
        waf = "Sucuri (probable)"
        add_ev("sucuri", sucuri)

    ev = " | ".join(evidence)[:320] if evidence else UNKNOWN
    return cdn, waf, ev


# -----------------------------
# Tool-based detection (agresivo)
# -----------------------------
def wafw00f_aggressive(domain: str) -> str:
    """
    Usa wafw00f si está instalado. Si no, devuelve "".
    Intenta modo más agresivo: --findall y --verbose cuando existen.
    """
    if not which("wafw00f"):
        return ""

    # Intentos por compatibilidad (distintas versiones)
    candidates = [
        ["wafw00f", "--findall", "-v", domain],
        ["wafw00f", "--findall", domain],
        ["wafw00f", "-v", domain],
        ["wafw00f", domain],
    ]
    for args in candidates:
        rc, out, err = run_cmd(args, timeout=25)
        txt = (out or "") + ("\n" + err if err else "")
        if txt.strip():
            # Reduce ruido, quedate con líneas relevantes
            lines = [l.strip() for l in txt.splitlines() if l.strip()]
            keep = []
            for l in lines:
                if any(x in l.lower() for x in ["is behind", "waf", "firewall", "identified", "checking", "site", "detected", "cloudflare", "akamai", "imperva", "sucuri", "f5", "fortinet"]):
                    keep.append(l)
            return "\n".join(keep[:30]) if keep else "\n".join(lines[:30])
    return ""


def whatweb_aggressive(domain: str) -> str:
    """
    Usa whatweb si está instalado. Nivel agresivo -a 3 (ruidoso).
    """
    if not which("whatweb"):
        return ""
    args = ["whatweb", "-a", "3", "--no-errors", domain]
    rc, out, err = run_cmd(args, timeout=25)
    txt = (out or "") + ("\n" + err if err else "")
    if not txt.strip():
        return ""
    lines = [l.strip() for l in txt.splitlines() if l.strip()]
    return "\n".join(lines[:20])


def summarize_tools(wafw00f_out: str, whatweb_out: str) -> Tuple[str, str, List[str]]:
    """
    Devuelve: waf_summary, whatweb_summary, extra_signals (strings)
    """
    extra: List[str] = []
    waf_sum = ""
    ww_sum = ""

    if wafw00f_out.strip():
        waf_sum = wafw00f_out.strip()[:1200]
        # señales de vendor
        low = wafw00f_out.lower()
        for v in ["akamai", "cloudflare", "imperva", "incapsula", "sucuri", "f5", "fortinet", "aws", "azure", "gcp"]:
            if v in low:
                extra.append(f"wafw00f:{v}")
    if whatweb_out.strip():
        ww_sum = whatweb_out.strip()[:1200]
        low = whatweb_out.lower()
        for v in ["akamai", "cloudflare", "fastly", "imperva", "incapsula", "sucuri"]:
            if v in low:
                extra.append(f"whatweb:{v}")

    return waf_sum, ww_sum, extra


# -----------------------------
# Gemini analysis (optional)
# -----------------------------
def gemini_analyze(domain: str, infra: InfraData) -> str:
    if CLIENT is None or MODEL_ID is None:
        return "Gemini no disponible."

    prompt = f"""
Rol: Senior Solutions Engineer (Akamai).
Regla: SOLO usar evidencia provista. Si falta evidencia, marcar como 'No concluyente'.

Dominio: {domain}

Evidencia:
- DNS A: {infra.a_records}
- CNAME chain: {infra.cname_chain}
- IP final: {infra.final_ip}
- WHOIS: owner={infra.whois_owner}, netname={infra.whois_netname}, cidr={infra.whois_cidr}, asn={infra.whois_asn}
- TLS: cn={infra.tls_cn}, issuer={infra.tls_issuer}, notAfter={infra.tls_not_after}
- Headers: server={infra.server_hdr}, sec_headers_ok(HSTS+CSP)={infra.sec_headers_ok}
- CDN vendor={infra.cdn_vendor}, WAF vendor={infra.waf_vendor}, evidence={infra.edge_evidence}
- Tools: wafw00f={'present' if infra.wafw00f_summary else 'none'}, whatweb={'present' if infra.whatweb_summary else 'none'}
- Origin bypass (heurístico): http={infra.origin_bypass_http}, https={infra.origin_bypass_https}
- Puertos abiertos (connect scan): {infra.open_ports}

Output:
5 bullets: (Observación) -> (Riesgo) -> (Acción recomendada). Sin inventar vendors.
"""
    try:
        res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
        txt = getattr(res, "text", None)
        return (txt or str(res))[:3000].strip()
    except Exception as e:
        return f"Gemini error: {e!r}"


# -----------------------------
# Main infra collection
# -----------------------------
@st.cache_data(show_spinner=False, ttl=600)
def get_infra_data(domain: str, verify_tls: bool, run_tools: bool) -> InfraData:
    t0 = time.time()
    errors: List[str] = []
    notes: List[str] = []
    debug: Dict[str, Any] = {"verify_tls": verify_tls, "timing": {}}

    # DNS
    a_records, cname_chain, dns_errs = resolve_dns(domain, timeout=3.0)
    errors.extend(dns_errs)
    final_ip = a_records[-1] if a_records else UNKNOWN

    # WHOIS (consistent)
    who_owner, who_cidr, who_asn, who_netname, who_raw = ip_whois(final_ip)
    if who_raw:
        debug["whois_raw_present"] = True

    # Ports
    common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8008, 8888, 9200, 5601, 2082, 2083, 2086, 2087]
    open_ports = scan_ports(domain, common_ports, timeout=0.6, max_workers=64)

    # TLS
    tls_cn, tls_san, tls_issuer, tls_not_after, tls_errs = tls_details(domain, timeout=5.0)
    errors.extend(tls_errs)

    # HTTP headers (multi probes)
    sess = build_requests_session(total_retries=2, backoff=0.25)
    headers, hdr_errs, hdr_dbg = collect_headers_multi(sess, domain, verify_tls=verify_tls)
    errors.extend(hdr_errs)
    debug["http"] = hdr_dbg

    server_hdr, sec_headers_ok = analyze_headers(headers)

    # Tools (wafw00f/whatweb) - “agresivos” pero opcionales
    wafw00f_out = ""
    whatweb_out = ""
    extra_signals: List[str] = []
    if run_tools:
        wafw00f_out = wafw00f_aggressive(domain)
        whatweb_out = whatweb_aggressive(domain)
        wafw00f_sum, whatweb_sum, extra_signals = summarize_tools(wafw00f_out, whatweb_out)
    else:
        wafw00f_sum, whatweb_sum = "", ""

    # Vendor inference (CDN/WAF)
    cdn_vendor, waf_vendor, edge_evidence = detect_edge_vendor(domain, headers, cname_chain, extra_signals)

    # Origin bypass heuristic
    origin_http_bypass, origin_https_bypass, bypass_errs = origin_bypass_checks(sess, domain, final_ip, timeout=4.0)
    errors.extend(bypass_errs)

    if origin_http_bypass or origin_https_bypass:
        notes.append("Bypass heurístico: respuesta válida desde IP con Host header. Confirmar comparando contenido/headers vs edge.")
    if final_ip == UNKNOWN:
        notes.append("Sin A record resoluble: input inválido, DNS roto, o resolución bloqueada.")
    if cdn_vendor == UNKNOWN and waf_vendor == UNKNOWN:
        notes.append("Sin señales suficientes para CDN/WAF con probes actuales. Resultado: No detectado.")

    debug["timing"]["total_s"] = round(time.time() - t0, 3)

    return InfraData(
        domain=domain,
        a_records=a_records,
        cname_chain=cname_chain,
        final_ip=final_ip,
        whois_owner=who_owner,
        whois_cidr=who_cidr,
        whois_asn=who_asn,
        whois_netname=who_netname,
        whois_raw=who_raw[:40000] if who_raw else "",
        open_ports=open_ports,
        origin_bypass_http=origin_http_bypass,
        origin_bypass_https=origin_https_bypass,
        tls_cn=tls_cn,
        tls_san=tls_san,
        tls_issuer=tls_issuer,
        tls_not_after=tls_not_after,
        headers={k: str(v) for k, v in (headers or {}).items()},
        server_hdr=server_hdr,
        cdn_vendor=cdn_vendor,
        waf_vendor=waf_vendor,
        edge_evidence=edge_evidence,
        wafw00f_summary=wafw00f_sum if run_tools else "",
        whatweb_summary=whatweb_sum if run_tools else "",
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
    verify_tls = st.toggle("Verificar TLS", value=True, help="Si el sitio tiene cert inválido, desactiva para no cortar evidencia de headers.")
    run_tools = st.toggle("Detección agresiva (wafw00f/whatweb)", value=True, help="Usa binarios locales si existen. Si no están, se ignora.")
    show_debug = st.toggle("Mostrar debug", value=False)
    st.caption("CDN/WAF es inferencia. Si no hay evidencia: 'No detectado'. WHOIS usa ipwhois si existe; si no, cae a `whois` del sistema.")

target = st.text_input("Dominio o URL:", placeholder="empresa.com / https://empresa.com", label_visibility="collapsed")
run = st.button("🚀 Iniciar Auditoría Ninja", type="primary")

if run:
    dom = normalize_target(target)
    if not is_valid_domain(dom):
        st.error("Input inválido. Esperado: dominio FQDN tipo 'empresa.com'.")
        st.stop()

    with st.status("Analizando infraestructura...", expanded=False) as status:
        infra = get_infra_data(dom, verify_tls=verify_tls, run_tools=run_tools)
        status.update(label="Análisis de infraestructura completo", state="complete")

    # -------------------------
    # Metrics (4 + 4)
    # -------------------------
    c1, c2, c3, c4 = st.columns(4)

    # WHOIS delta: netname + asn
    who_delta = f"{infra.whois_netname} | {infra.whois_asn}" if infra.whois_netname != UNKNOWN or infra.whois_asn != UNKNOWN else None
    c1.metric("IP final (A)", infra.final_ip, who_delta)

    c2.metric("TLS CN", (infra.tls_cn or UNKNOWN)[:28], (infra.tls_not_after or UNKNOWN)[:28])

    bypass_state = "VULNERABLE" if (infra.origin_bypass_http or infra.origin_bypass_https) else "Protegido"
    c3.metric("Bypass origin", bypass_state, delta="- Riesgo Alto" if bypass_state == "VULNERABLE" else None, delta_color="inverse")

    # Mostrar CIDR como "detalle importante"
    c4.metric("WHOIS (CIDR)", infra.whois_cidr, infra.whois_owner[:28] if infra.whois_owner != UNKNOWN else None)

    c1b, c2b, c3b, c4b = st.columns(4)
    c1b.metric("Server header", (infra.server_hdr or UNKNOWN)[:28])
    c2b.metric("CDN", infra.cdn_vendor)
    c3b.metric("WAF", infra.waf_vendor)
    c4b.metric("Security (HSTS+CSP)", "✅ OK" if infra.sec_headers_ok else "❌ Missing")

    st.divider()

    tab_brief, tab_tech = st.tabs(["⚡ Briefing", "🛠️ Técnico"])

    with tab_brief:
        if CLIENT is not None and MODEL_ID is not None:
            with st.spinner("Generando briefing con Gemini..."):
                txt = gemini_analyze(dom, infra)
            st.info(txt)
        else:
            # fallback determinístico
            bullets = []
            if infra.cdn_vendor != UNKNOWN or infra.waf_vendor != UNKNOWN:
                bullets.append(f"CDN/WAF inferido -> {infra.cdn_vendor} / {infra.waf_vendor} -> validar con evidencia (CNAME/headers/tools).")
            else:
                bullets.append("CDN/WAF -> No detectado -> sin señales suficientes en headers/DNS/tools.")
            if infra.origin_bypass_http or infra.origin_bypass_https:
                bullets.append("Origin bypass (heurístico) -> posible exposición -> bloquear acceso directo a origen (ACL/allowlist/mTLS).")
            if not infra.sec_headers_ok:
                bullets.append("HSTS/CSP missing -> hardening insuficiente -> definir HSTS y CSP por app.")
            if any(p in infra.open_ports for p in [8080, 8443, 3000, 5000, 8000, 8888, 9200, 5601]):
                bullets.append(f"Puertos no estándar {infra.open_ports} -> superficie extra -> restringir por firewall/VPN.")
            bullets.append(f"WHOIS -> {infra.whois_owner} | {infra.whois_netname} | {infra.whois_cidr} | {infra.whois_asn}")
            st.info("\n".join([f"- {b}" for b in bullets[:5]]))

        if infra.notes:
            st.caption("Notas")
            st.write("\n".join([f"- {n}" for n in infra.notes]))

        if infra.errors:
            st.caption("Errores")
            st.write("\n".join([f"- {e}" for e in infra.errors[:20]]))

    with tab_tech:
        st.write(f"**CNAME chain:** `{infra.cname_chain}`")
        st.write(f"**A records:** `{infra.a_records}`")
        st.write(f"**Puertos abiertos:** `{infra.open_ports}`")

        st.write("**Resumen estructurado:**")
        st.json(
            {
                "domain": infra.domain,
                "dns": {"a": infra.a_records, "cname_chain": infra.cname_chain, "final_ip": infra.final_ip},
                "whois": {"owner": infra.whois_owner, "netname": infra.whois_netname, "asn": infra.whois_asn, "cidr": infra.whois_cidr},
                "tls": {"cn": infra.tls_cn, "san": infra.tls_san[:25], "issuer": infra.tls_issuer, "not_after": infra.tls_not_after},
                "http": {"server": infra.server_hdr, "sec_headers_ok": infra.sec_headers_ok},
                "edge": {"cdn_vendor": infra.cdn_vendor, "waf_vendor": infra.waf_vendor, "evidence": infra.edge_evidence},
                "bypass": {"http": infra.origin_bypass_http, "https": infra.origin_bypass_https},
            }
        )

        with st.expander("Evidencia Edge (CDN/WAF)"):
            st.code(infra.edge_evidence or UNKNOWN)

        with st.expander("Headers crudos"):
            st.code("\n".join([f"{k}: {v}" for k, v in infra.headers.items()]) or UNKNOWN)

        if infra.wafw00f_summary:
            with st.expander("wafw00f (agresivo)"):
                st.code(infra.wafw00f_summary)

        if infra.whatweb_summary:
            with st.expander("whatweb (-a 3)"):
                st.code(infra.whatweb_summary)

        if infra.whois_raw:
            with st.expander("WHOIS crudo"):
                st.code(infra.whois_raw)

        if show_debug:
            with st.expander("Debug"):
                st.json(infra.debug)
