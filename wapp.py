# wapp.py
# Pentest ligero (recon + hardening) orientado a preventa: poco wording, muchas alertas/bullets.
# Nota: ejecutá solo con autorización.

import re
import time
import json
import socket
import ssl
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import streamlit as st
from fpdf import FPDF

# -----------------------
# Optional: Gemini (si está)
# -----------------------
try:
    from google import genai
except Exception:
    genai = None

# -----------------------
# Streamlit config
# -----------------------
st.set_page_config(page_title="EdgeSight SE - Light PT", layout="wide")

UA = "EdgeSightSE-LightPT/1.2"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

# -----------------------
# Top 100 (web + infra) - lista práctica
# -----------------------
TOP100_WEB_INFRA = [
    # Web
    80, 81, 88, 443, 444, 591, 593, 8000, 8008, 8010, 8080, 8081, 8088, 8090, 8181, 8222,
    8443, 8444, 8888, 9000, 9090, 9443,
    # Admin panels / proxies / app servers
    2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4000, 4440, 5000, 5001, 5601, 5984,
    7001, 7002, 7080, 7443, 7777, 8880, 9200, 9300,
    # Infra common
    21, 22, 23, 25, 53, 67, 68, 69, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389,
    445, 512, 513, 514, 515, 587, 631, 636, 873, 902, 989, 990, 993, 995,
    # DB/cache/search/queue
    1433, 1521, 1830, 2049, 2375, 2376, 2483, 2484, 27017, 27018, 27019, 28017, 3306, 3389,
    50000, 5432, 5672, 5671, 5900, 5985, 5986, 6379, 6380, 7199,
    8082, 8500, 8778, 9042, 9160, 11211, 15672, 16379, 2181, 9092
]
TOP100_WEB_INFRA = sorted(list(dict.fromkeys(TOP100_WEB_INFRA)))[:100]  # asegura 100 únicos

SENSITIVE_PATHS = [
    "/.git/", "/.env", "/.DS_Store", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/config.php.bak", "/config.yml", "/config.json", "/phpinfo.php",
    "/server-status", "/server-status?auto",
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
    "/admin/", "/administrator/", "/login/", "/signin/", "/console", "/manage", "/manager/html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/swagger", "/swagger-ui", "/swagger-ui/index.html", "/openapi.json",
    "/graphql", "/.well-known/security.txt"
]

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# -----------------------
# Helpers
# -----------------------
def normalize_domain(raw: str) -> Optional[str]:
    if not raw:
        return None
    x = raw.strip().lower()
    x = x.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
    return x if DOMAIN_RE.match(x) else None


def run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        if res.returncode == 0:
            return True, out
        return (bool(out), out or err or f"returncode={res.returncode}")
    except FileNotFoundError:
        return False, f"missing_tool={cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"timeout={' '.join(cmd)}"
    except Exception as e:
        return False, f"error={' '.join(cmd)} :: {e}"


def resolve_dns(domain: str) -> Dict[str, List[str]]:
    # Usa dig si existe. Fallback simple.
    dns = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    for rr in dns.keys():
        ok, out = run_cmd(["dig", "+short", rr, domain], timeout=5)
        if ok and out:
            vals = [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]
            dns[rr] = vals
    if not dns["A"]:
        try:
            dns["A"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
    return dns


def get_owner_whois(ip: str) -> str:
    if not ip:
        return "N/A"
    ok, out = run_cmd(["whois", ip], timeout=8)
    if not ok or not out:
        return "N/A"
    keys = ("org-name", "orgname", "organization", "descr", "netname", "owner")
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in keys) and ":" in line:
            return line.split(":", 1)[1].strip()[:90]
    return "N/A"


def check_port(host: str, port: int, timeout: float = 0.55) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_ports(host: str, ports: List[int], workers: int = 64) -> List[int]:
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as ex:
        futs = {ex.submit(check_port, host, p): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


def tls_not_after(domain: str) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert.get("notAfter", "N/A")
    except Exception:
        return "N/A"


def tls_probe_versions(domain: str) -> Dict[str, str]:
    """
    Probe simple: intenta handshake con TLS1.0/1.1/1.2/1.3 (si disponible).
    No es un auditor completo, pero da señales.
    """
    results = {}
    versions = []
    # Compat python: SSLContext.minimum_version / maximum_version
    if hasattr(ssl, "TLSVersion"):
        versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
    else:
        return {"TLS": "unknown_python_ssl"}

    for name, v in versions:
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = v
            ctx.maximum_version = v
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    _ = ssock.version()
                    results[name] = "on"
        except Exception:
            results[name] = "off"
    return results


def http_fetch(domain: str, scheme: str, verify_tls: bool, timeout: int = 7) -> Tuple[Optional[requests.Response], Optional[str]]:
    url = f"{scheme}://{domain}"
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": UA},
            verify=verify_tls,
            allow_redirects=True,
        )
        return r, None
    except requests.exceptions.SSLError as e:
        return None, f"ssl_error={e}"
    except Exception as e:
        return None, f"http_error={e}"


def headers_audit(h: Dict[str, str]) -> Tuple[int, List[str]]:
    """
    Score 0..6 + findings bullets
    """
    score = 0
    bullets = []
    for k in SEC_HEADERS:
        if k in h and h.get(k):
            score += 1
        else:
            bullets.append(f"MISS {k}")
    # CSP quick smell
    csp = h.get("Content-Security-Policy", "")
    if csp:
        weak = any(x in csp for x in ["unsafe-inline", "unsafe-eval", "*", "data:"])
        if weak:
            bullets.append("WEAK CSP")
    return score, bullets


def detect_cdn_signals(h: Dict[str, str]) -> List[str]:
    sig = []
    # Muy simple: señales por headers
    for k in ["Server", "Via", "X-Cache", "CF-RAY", "CF-Cache-Status", "X-Akamai-Transformed", "X-CDN", "Fastly-FF"]:
        if k in h and h.get(k) not in (None, "", "N/A"):
            sig.append(f"{k}={h.get(k)[:60]}")
    return sig


def methods_probe(domain: str, verify_tls: bool) -> List[str]:
    url = f"https://{domain}"
    try:
        r = requests.options(url, timeout=6, headers={"User-Agent": UA}, verify=verify_tls, allow_redirects=True)
        allow = r.headers.get("Allow", "") or r.headers.get("access-control-allow-methods", "")
        allow = allow.upper()
        flags = []
        for m in ["TRACE", "TRACK", "PUT", "DELETE"]:
            if m in allow:
                flags.append(f"ALLOW {m}")
        if allow:
            flags.append(f"ALLOW={allow[:120]}")
        return flags
    except Exception:
        return []


def rate_limit_probe(domain: str, verify_tls: bool, n: int = 25) -> Dict[str, str]:
    """
    Ligero: 25 requests a / (sin brute). Detecta 429 / 403 / captchas por señales.
    """
    url = f"https://{domain}/"
    codes = {}
    start = time.time()
    last = None
    for _ in range(n):
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": UA}, verify=verify_tls, allow_redirects=True)
            last = r.status_code
            codes[str(r.status_code)] = codes.get(str(r.status_code), 0) + 1
            if r.status_code in (429, 403):
                break
        except Exception:
            codes["err"] = codes.get("err", 0) + 1
            break
    elapsed = time.time() - start
    return {"counts": json.dumps(codes), "elapsed_s": f"{elapsed:.2f}", "last": str(last) if last is not None else "N/A"}


def sensitive_paths_probe(domain: str, verify_tls: bool, max_hits: int = 12) -> List[str]:
    """
    Sólo HEAD/GET liviano. Marca 200/206/301/302/401/403.
    """
    hits = []
    for path in SENSITIVE_PATHS:
        url = f"https://{domain}{path}"
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent": UA}, verify=verify_tls, allow_redirects=False)
            if r.status_code in (200, 206, 301, 302, 401, 403):
                hits.append(f"{r.status_code} {path}")
            if len(hits) >= max_hits:
                break
        except Exception:
            continue
    return hits


def ip_direct_probe(domain: str, ips: List[str], verify_tls: bool) -> List[str]:
    """
    Señal de bypass: intenta HTTP por IP con Host header.
    No hace explotación, sólo compara status/Server.
    """
    findings = []
    for ip in ips[:3]:
        try:
            url = f"http://{ip}/"
            r = requests.get(url, timeout=6, headers={"User-Agent": UA, "Host": domain}, verify=False, allow_redirects=False)
            srv = r.headers.get("Server", "N/A")[:40]
            findings.append(f"IP_DIRECT {ip} {r.status_code} Server={srv}")
        except Exception:
            continue
    return findings


def waf_fingerprint(domain: str) -> str:
    ok, out = run_cmd(["wafw00f", domain], timeout=14)
    if ok and out:
        return out
    return f"[{out}]"


def whatweb_fingerprint(domain: str) -> str:
    ok, out = run_cmd(["whatweb", domain], timeout=14)
    if ok and out:
        return out
    return f"[{out}]"


# -----------------------
# Data model
# -----------------------
@dataclass
class Snapshot:
    domain: str
    dns: Dict[str, List[str]]
    ip_primary: str
    owner: str
    open_ports: List[int]
    tls_not_after: str
    tls_versions: Dict[str, str]
    http_status: str
    https_status: str
    headers: Dict[str, str]
    sec_headers_score: int
    sec_headers_findings: List[str]
    cdn_signals: List[str]
    methods_flags: List[str]
    rate_limit: Dict[str, str]
    sensitive_hits: List[str]
    ip_direct_findings: List[str]
    wafw00f: str
    whatweb: str


def build_pdf(s: Snapshot, bullets: List[str]) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)

    pdf.set_font("Arial", "B", 13)
    pdf.cell(0, 8, f"EdgeSight SE - Light PT :: {s.domain}", ln=True)

    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 5, f"IP={s.ip_primary} | Owner={s.owner} | Ports={s.open_ports}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 5, f"TLS notAfter={s.tls_not_after} | TLS={s.tls_versions}".encode("latin-1","replace").decode("latin-1"))

    pdf.ln(1)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Bullets", ln=True)
    pdf.set_font("Arial", "", 10)
    for b in bullets:
        pdf.multi_cell(0, 5, f"- {b}".encode("latin-1","replace").decode("latin-1"))

    pdf.ln(1)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Raw (short)", ln=True)
    pdf.set_font("Arial", "", 9)
    pdf.multi_cell(0, 4, f"Headers={s.headers}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 4, f"CDN={s.cdn_signals}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 4, f"Sensitive={s.sensitive_hits}".encode("latin-1","replace").decode("latin-1"))

    return bytes(pdf.output())


# -----------------------
# Gemini boot (optional)
# -----------------------
@st.cache_resource
def boot_gemini():
    if genai is None:
        return None, None, "genai_sdk_missing"
    try:
        key = st.secrets.get("GEMINI_API_KEY", None)
        if not key:
            return None, None, "missing_GEMINI_API_KEY"
        client = genai.Client(api_key=key)
        return client, "gemini-2.0-flash", None
    except Exception as e:
        return None, None, f"gemini_init_error={e}"


CLIENT, MODEL_ID, GEMINI_ERR = boot_gemini()


def gemini_bullets(snapshot: Snapshot) -> List[str]:
    if not CLIENT or not MODEL_ID:
        return []
    # prompt minimal, output bullets secos
    prompt = f"""
Input (no inventar):
domain={snapshot.domain}
ip={snapshot.ip_primary}
owner={snapshot.owner}
open_ports={snapshot.open_ports}
dns={snapshot.dns}
tls_not_after={snapshot.tls_not_after}
tls_versions={snapshot.tls_versions}
sec_headers_score={snapshot.sec_headers_score}
sec_headers_findings={snapshot.sec_headers_findings}
cdn_signals={snapshot.cdn_signals}
methods_flags={snapshot.methods_flags}
rate_limit={snapshot.rate_limit}
sensitive_hits={snapshot.sensitive_hits}
ip_direct_findings={snapshot.ip_direct_findings}
whatweb={snapshot.whatweb[:400]}
wafw00f={snapshot.wafw00f[:400]}

Output:
- 8 bullets técnicos, ultra cortos.
- Prefijo por severidad: [CRIT]/[HIGH]/[MED]/[LOW]/[INFO]
- No relleno, no marketing.
- Si falta evidencia: "No observado".
""".strip()

    try:
        res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
        text = getattr(res, "text", "") or ""
        # parse simple: bullets por línea
        lines = [l.strip("•- \t") for l in text.splitlines() if l.strip()]
        # filtra cosas raras
        out = []
        for l in lines:
            if len(l) < 3:
                continue
            out.append(l[:240])
        return out[:12]
    except Exception:
        return []


# -----------------------
# UI
# -----------------------
st.title("🛡️ EdgeSight SE :: Light PT (Preventa técnico)")

col1, col2, col3 = st.columns([3, 2, 2])
with col1:
    raw = st.text_input("Dominio", placeholder="empresa.com", label_visibility="collapsed")
with col2:
    verify_tls = not st.checkbox("No verificar TLS (inseguro)", value=False)
with col3:
    aggressive = st.checkbox("Modo agresivo (más checks)", value=True)

with st.expander("Scan profile", expanded=False):
    ports = st.multiselect("Puertos", TOP100_WEB_INFRA, default=TOP100_WEB_INFRA)
    workers = st.slider("Concurrencia", 16, 128, 64, 16)
    rl_n = st.slider("Rate-limit probe (requests)", 10, 60, 25, 5)

run_btn = st.button("🚀 Run", type="primary")

if run_btn:
    dom = normalize_domain(raw)
    if not dom:
        st.error("Dominio inválido (ej: empresa.com)")
        st.stop()

    with st.status("Recon…", expanded=True) as status:
        status.write("DNS…")
        dns = resolve_dns(dom)
        ip_primary = dns["A"][0] if dns.get("A") else ""
        owner = get_owner_whois(ip_primary) if ip_primary else "N/A"

        status.write("Ports…")
        open_ports = scan_ports(dom, ports, workers=workers)

        status.write("HTTP/HTTPS…")
        r_http, e_http = http_fetch(dom, "http", verify_tls=verify_tls)
        r_https, e_https = http_fetch(dom, "https", verify_tls=verify_tls)

        headers = dict(r_https.headers) if r_https is not None else {}
        http_status = str(r_http.status_code) if r_http is not None else (e_http or "N/A")
        https_status = str(r_https.status_code) if r_https is not None else (e_https or "N/A")

        status.write("TLS…")
        not_after = tls_not_after(dom) if (443 in open_ports or 443 in ports) else "N/A"
        tls_versions = tls_probe_versions(dom) if (443 in open_ports or 443 in ports) else {"TLS": "N/A"}

        status.write("Headers audit…")
        sec_score, sec_findings = headers_audit(headers)

        status.write("Methods…")
        methods_flags = methods_probe(dom, verify_tls=verify_tls) if aggressive else []

        status.write("Rate-limit…")
        rate_limit = rate_limit_probe(dom, verify_tls=verify_tls, n=rl_n) if aggressive else {}

        status.write("Sensitive paths…")
        sensitive_hits = sensitive_paths_probe(dom, verify_tls=verify_tls) if aggressive else []

        status.write("CDN/IP-direct…")
        cdn_signals = detect_cdn_signals(headers)
        ip_direct_findings = ip_direct_probe(dom, dns.get("A", []), verify_tls=verify_tls) if aggressive else []

        status.write("Fingerprint…")
        waf = waf_fingerprint(dom) if aggressive else "skip"
        what = whatweb_fingerprint(dom) if aggressive else "skip"

        snapshot = Snapshot(
            domain=dom,
            dns=dns,
            ip_primary=ip_primary or "N/A",
            owner=owner,
            open_ports=open_ports,
            tls_not_after=not_after,
            tls_versions=tls_versions,
            http_status=http_status,
            https_status=https_status,
            headers={k: headers.get(k, "") for k in list(headers.keys())[:60]},
            sec_headers_score=sec_score,
            sec_headers_findings=sec_findings,
            cdn_signals=cdn_signals,
            methods_flags=methods_flags,
            rate_limit=rate_limit,
            sensitive_hits=sensitive_hits,
            ip_direct_findings=ip_direct_findings,
            wafw00f=waf,
            whatweb=what,
        )

        status.update(label="Done", state="complete", expanded=False)

    # -----------------------
    # Bullets + Alerts (muy escueto)
    # -----------------------
    bullets = []

    # Critical-ish heuristics
    if snapshot.ip_primary == "N/A" or snapshot.ip_primary == "":
        bullets.append("[HIGH] DNS A: No observado")
    if "TLSv1.0" in snapshot.tls_versions and snapshot.tls_versions.get("TLSv1.0") == "on":
        bullets.append("[HIGH] TLSv1.0: ON")
    if "TLSv1.1" in snapshot.tls_versions and snapshot.tls_versions.get("TLSv1.1") == "on":
        bullets.append("[MED] TLSv1.1: ON")
    if snapshot.sec_headers_score <= 2:
        bullets.append(f"[HIGH] SecHeaders score={snapshot.sec_headers_score}/6")
    elif snapshot.sec_headers_score <= 4:
        bullets.append(f"[MED] SecHeaders score={snapshot.sec_headers_score}/6")
    else:
        bullets.append(f"[INFO] SecHeaders score={snapshot.sec_headers_score}/6")

    if snapshot.sec_headers_findings:
        for f in snapshot.sec_headers_findings[:8]:
            bullets.append(f"[MED] {f}")

    # Open ports highlights
    risky_ports = [21, 23, 25, 110, 143, 389, 445, 1433, 1521, 2049, 2375, 27017, 3306, 3389, 5432, 6379, 9200, 11211]
    exposed = [p for p in snapshot.open_ports if p in risky_ports]
    if exposed:
        bullets.append(f"[HIGH] Exposed infra ports={exposed}")

    # Sensitive hits
    if snapshot.sensitive_hits:
        bullets.append(f"[HIGH] Sensitive endpoints hits={len(snapshot.sensitive_hits)}")
        for h in snapshot.sensitive_hits[:10]:
            bullets.append(f"[HIGH] {h}")

    # Methods flags
    for m in snapshot.methods_flags[:6]:
        if "TRACE" in m:
            bullets.append(f"[HIGH] {m}")
        else:
            bullets.append(f"[MED] {m}")

    # Rate-limit
    if snapshot.rate_limit:
        bullets.append(f"[INFO] RateLimit counts={snapshot.rate_limit.get('counts')} last={snapshot.rate_limit.get('last')}")

    # CDN/IP direct
    if snapshot.cdn_signals:
        bullets.append(f"[INFO] CDN signals={len(snapshot.cdn_signals)}")
        for sgn in snapshot.cdn_signals[:6]:
            bullets.append(f"[INFO] {sgn}")
    if snapshot.ip_direct_findings:
        bullets.append("[MED] IP-direct (Host header) responses observed")
        for it in snapshot.ip_direct_findings[:3]:
            bullets.append(f"[MED] {it}")

    # Fingerprint snippets
    if snapshot.whatweb and snapshot.whatweb != "skip":
        bullets.append("[INFO] whatweb: observed")
    if snapshot.wafw00f and snapshot.wafw00f != "skip":
        bullets.append("[INFO] wafw00f: observed")

    # Gemini bullets (si hay)
    ai_bullets = gemini_bullets(snapshot)
    if ai_bullets:
        bullets = ai_bullets + bullets  # AI arriba
    else:
        if GEMINI_ERR:
            bullets.insert(0, f"[INFO] gemini={GEMINI_ERR}")

    # -----------------------
    # Dashboard
    # -----------------------
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("IP", snapshot.ip_primary, snapshot.owner[:22] if snapshot.owner else "")
    c2.metric("HTTPS", snapshot.https_status)
    c3.metric("Ports open", len(snapshot.open_ports))
    c4.metric("SecHeaders", f"{snapshot.sec_headers_score}/6")
    cdn = "YES" if snapshot.cdn_signals else "NO"
    c5.metric("CDN signals", cdn)

    st.markdown("---")

    left, right = st.columns([2, 1])

    with left:
        st.subheader("Alerts / Bullets")
        # alertas compactas por severidad
        for b in bullets[:40]:
            if b.startswith("[CRIT]") or b.startswith("[HIGH]"):
                st.error(b)
            elif b.startswith("[MED]"):
                st.warning(b)
            else:
                st.info(b)

    with right:
        st.subheader("Raw (short)")
        st.write(f"**DNS A:** `{snapshot.dns.get('A', [])}`")
        st.write(f"**DNS AAAA:** `{snapshot.dns.get('AAAA', [])}`")
        st.write(f"**CNAME:** `{snapshot.dns.get('CNAME', [])}`")
        st.write(f"**MX:** `{snapshot.dns.get('MX', [])}`")
        st.write(f"**TLS notAfter:** `{snapshot.tls_not_after}`")
        st.write(f"**TLS versions:** `{snapshot.tls_versions}`")
        st.write(f"**Open ports:** `{snapshot.open_ports}`")
        st.write("**Headers:**")
        st.json(snapshot.headers)

        with st.expander("Fingerprint outputs", expanded=False):
            st.write("wafw00f")
            st.code(snapshot.wafw00f[:2000] if snapshot.wafw00f else "N/A")
            st.write("whatweb")
            st.code(snapshot.whatweb[:2000] if snapshot.whatweb else "N/A")

        with st.expander("Snapshot JSON", expanded=False):
            st.code(json.dumps(asdict(snapshot), indent=2)[:10000])

    # -----------------------
    # PDF
    # -----------------------
    pdf_bytes = build_pdf(snapshot, bullets[:60])
    st.download_button("📥 PDF", data=pdf_bytes, file_name=f"{dom}-lightpt.pdf", mime="application/pdf")

    # -----------------------
    # Quick next actions (muy seco)
    # -----------------------
    st.markdown("---")
    st.subheader("Next actions (dry)")
    nexts = []
    if snapshot.sec_headers_score < 5:
        nexts.append("- Harden security headers (HSTS/CSP/XFO/XCTO/RP/PP)")
    if snapshot.tls_versions.get("TLSv1.0") == "on" or snapshot.tls_versions.get("TLSv1.1") == "on":
        nexts.append("- Disable legacy TLS (1.0/1.1), enforce modern ciphers")
    if exposed:
        nexts.append(f"- Close/segment exposed infra ports: {exposed}")
    if snapshot.ip_direct_findings:
        nexts.append("- Validate CDN bypass controls (origin ACL, mTLS, auth, IP allowlist)")
    if snapshot.sensitive_hits:
        nexts.append("- Remove/protect sensitive endpoints & backups")
    if not nexts:
        nexts.append("- Deeper scan: subdomains (CT logs) + vulns scan (authz-based)")

    st.code("\n".join(nexts))
