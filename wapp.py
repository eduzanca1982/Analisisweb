# app.py
# EdgeSight SE - Light PT (preventa técnico) - "bulletproof"
# - 1 solo llamado a Gemini por corrida (cuando ya está TODO el output)
# - cache + session_state (evita reruns llamando de nuevo)
# - retry/backoff sólo para 429 RESOURCE_EXHAUSTED
# - degrada sin romper si faltan tools (dig/whois/wafw00f/whatweb)
# - wording mínimo: bullets + alerts
#
# Ejecutá sólo con autorización.

import hashlib
import json
import random
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import requests
import streamlit as st
from fpdf import FPDF

# Optional Gemini
try:
    from google import genai
except Exception:
    genai = None

# -----------------------
# Streamlit
# -----------------------
st.set_page_config(page_title="EdgeSight SE - Light PT", layout="wide")

UA = "EdgeSightSE-LightPT/2.0"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

# -----------------------
# Ports (Top 100 web + infra)
# -----------------------
TOP100_WEB_INFRA = sorted(list(dict.fromkeys([
    # Web
    80, 81, 88, 443, 444, 591, 593, 8000, 8008, 8010, 8080, 8081, 8088, 8090, 8181, 8222,
    8443, 8444, 8888, 9000, 9090, 9443,
    # Admin/proxy/app
    2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4000, 4440, 5000, 5001, 5601, 5984,
    7001, 7002, 7080, 7443, 7777, 8880, 9200, 9300,
    # Infra common
    21, 22, 23, 25, 53, 67, 68, 69, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389,
    445, 512, 513, 514, 515, 587, 631, 636, 873, 902, 989, 990, 993, 995,
    # DB/cache/search/queue
    1433, 1521, 1830, 2049, 2375, 2376, 2483, 2484,
    27017, 27018, 27019, 28017, 3306, 3389, 50000, 5432,
    5672, 5671, 5900, 5985, 5986, 6379, 6380, 7199,
    8082, 8500, 8778, 9042, 9160, 11211, 15672, 16379, 2181, 9092
])))[:100]

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

RISKY_PORTS = [21, 23, 25, 110, 143, 389, 445, 1433, 1521, 2049, 2375, 27017, 3306, 3389, 5432, 6379, 9200, 11211]


# -----------------------
# Helpers
# -----------------------
def normalize_domain(raw: str) -> Optional[str]:
    if not raw:
        return None
    x = raw.strip().lower()
    x = x.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
    return x if DOMAIN_RE.match(x) else None


def run_cmd(cmd: List[str], timeout: int = 12) -> Tuple[bool, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        if res.returncode == 0:
            return True, out
        # tools a veces devuelven !=0 con output útil
        return (bool(out), out or err or f"returncode={res.returncode}")
    except FileNotFoundError:
        return False, f"missing_tool={cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"timeout={' '.join(cmd)}"
    except Exception as e:
        return False, f"error={' '.join(cmd)} :: {e}"


def resolve_dns(domain: str) -> Dict[str, List[str]]:
    dns = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    for rr in list(dns.keys()):
        ok, out = run_cmd(["dig", "+short", rr, domain], timeout=5)
        if ok and out:
            dns[rr] = [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]
    if not dns["A"]:
        try:
            dns["A"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
    return dns


def whois_owner(ip: str) -> str:
    if not ip or ip == "N/A":
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
    open_ports: List[int] = []
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
    if not hasattr(ssl, "TLSVersion"):
        return {"TLS": "unknown_python_ssl"}

    versions = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    out: Dict[str, str] = {}
    for name, v in versions:
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = v
            ctx.maximum_version = v
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    _ = ssock.version()
                    out[name] = "on"
        except Exception:
            out[name] = "off"
    return out


def http_fetch(domain: str, scheme: str, verify_tls: bool) -> Tuple[Optional[requests.Response], str]:
    url = f"{scheme}://{domain}"
    try:
        r = requests.get(
            url,
            timeout=7,
            headers={"User-Agent": UA},
            verify=verify_tls,
            allow_redirects=True,
        )
        return r, ""
    except requests.exceptions.SSLError as e:
        return None, f"ssl_error={e}"
    except Exception as e:
        return None, f"http_error={e}"


def headers_audit(h: Dict[str, str]) -> Tuple[int, List[str]]:
    score = 0
    findings: List[str] = []
    for k in SEC_HEADERS:
        if h.get(k):
            score += 1
        else:
            findings.append(f"MISS {k}")
    csp = h.get("Content-Security-Policy", "")
    if csp:
        if any(x in csp for x in ["unsafe-inline", "unsafe-eval", "*", "data:"]):
            findings.append("WEAK CSP")
    return score, findings


def detect_cdn_signals(h: Dict[str, str]) -> List[str]:
    sig = []
    keys = ["Server", "Via", "X-Cache", "CF-RAY", "CF-Cache-Status", "X-Akamai-Transformed", "X-CDN", "Fastly-FF"]
    for k in keys:
        v = h.get(k)
        if v:
            sig.append(f"{k}={str(v)[:60]}")
    return sig


def methods_probe(domain: str, verify_tls: bool) -> List[str]:
    url = f"https://{domain}"
    try:
        r = requests.options(url, timeout=6, headers={"User-Agent": UA}, verify=verify_tls, allow_redirects=True)
        allow = (r.headers.get("Allow", "") or r.headers.get("access-control-allow-methods", "")).upper()
        if not allow:
            return []
        flags = [f"ALLOW={allow[:120]}"]
        for m in ["TRACE", "TRACK", "PUT", "DELETE"]:
            if m in allow:
                flags.append(f"ALLOW {m}")
        return flags
    except Exception:
        return []


def rate_limit_probe(domain: str, verify_tls: bool, n: int = 25) -> Dict[str, str]:
    url = f"https://{domain}/"
    codes: Dict[str, int] = {}
    start = time.time()
    last = None
    for _ in range(n):
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": UA}, verify=verify_tls, allow_redirects=True)
            last = r.status_code
            k = str(r.status_code)
            codes[k] = codes.get(k, 0) + 1
            if r.status_code in (429, 403):
                break
        except Exception:
            codes["err"] = codes.get("err", 0) + 1
            break
    return {"counts": json.dumps(codes), "elapsed_s": f"{(time.time()-start):.2f}", "last": str(last) if last is not None else "N/A"}


def sensitive_paths_probe(domain: str, verify_tls: bool, max_hits: int = 12) -> List[str]:
    hits: List[str] = []
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


def ip_direct_probe(domain: str, ips: List[str]) -> List[str]:
    findings: List[str] = []
    for ip in ips[:3]:
        try:
            url = f"http://{ip}/"
            r = requests.get(url, timeout=6, headers={"User-Agent": UA, "Host": domain}, verify=False, allow_redirects=False)
            srv = (r.headers.get("Server", "N/A") or "N/A")[:40]
            findings.append(f"IP_DIRECT {ip} {r.status_code} Server={srv}")
        except Exception:
            continue
    return findings


def waf_fingerprint(domain: str) -> str:
    ok, out = run_cmd(["wafw00f", domain], timeout=16)
    return out if ok and out else f"[{out}]"


def whatweb_fingerprint(domain: str) -> str:
    ok, out = run_cmd(["whatweb", domain], timeout=16)
    return out if ok and out else f"[{out}]"


# -----------------------
# Snapshot model
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


def snapshot_key(s: Snapshot) -> str:
    payload = json.dumps(asdict(s), sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def build_pdf(snapshot: Snapshot, bullets: List[str]) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=10)

    pdf.set_font("Arial", "B", 13)
    pdf.cell(0, 8, f"EdgeSight SE - Light PT :: {snapshot.domain}", ln=True)

    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 5, f"IP={snapshot.ip_primary} | Owner={snapshot.owner} | Ports={snapshot.open_ports}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 5, f"TLS notAfter={snapshot.tls_not_after} | TLS={snapshot.tls_versions}".encode("latin-1","replace").decode("latin-1"))

    pdf.ln(1)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Bullets", ln=True)
    pdf.set_font("Arial", "", 10)
    for b in bullets[:80]:
        pdf.multi_cell(0, 5, f"- {b}".encode("latin-1","replace").decode("latin-1"))

    pdf.ln(1)
    pdf.set_font("Arial", "B", 11)
    pdf.cell(0, 6, "Raw (short)", ln=True)
    pdf.set_font("Arial", "", 9)
    pdf.multi_cell(0, 4, f"Headers={snapshot.headers}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 4, f"CDN={snapshot.cdn_signals}".encode("latin-1","replace").decode("latin-1"))
    pdf.multi_cell(0, 4, f"Sensitive={snapshot.sensitive_hits}".encode("latin-1","replace").decode("latin-1"))

    return bytes(pdf.output())


# -----------------------
# Gemini (single call) + retry + cache
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
        return client, "gemini-2.0-flash", ""
    except Exception as e:
        return None, None, f"gemini_init_error={e}"


CLIENT, MODEL_ID, GEMINI_ERR = boot_gemini()


def gemini_generate_with_retry(prompt: str,
                              max_retries: int = 5,
                              base_sleep: float = 1.2,
                              max_sleep: float = 14.0) -> Tuple[bool, str]:
    if not CLIENT or not MODEL_ID:
        return False, (GEMINI_ERR or "gemini_unavailable")

    last_err = ""
    for attempt in range(max_retries + 1):
        try:
            res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
            text = getattr(res, "text", "") or ""
            return True, text
        except Exception as e:
            msg = str(e)
            last_err = msg
            is_429 = ("429" in msg) or ("RESOURCE_EXHAUSTED" in msg)
            if not is_429:
                return False, f"gemini_error={msg}"

            if attempt >= max_retries:
                return False, f"gemini_429_exhausted={msg}"

            sleep_s = min(max_sleep, base_sleep * (2 ** attempt)) * (0.7 + random.random() * 0.6)
            time.sleep(sleep_s)

    return False, f"gemini_error={last_err}"


@st.cache_data(ttl=900)
def cached_ai_bullets(model_id: str, snap_key: str, prompt: str) -> List[str]:
    ok, text = gemini_generate_with_retry(prompt)
    if not ok:
        return [f"[INFO] {text[:220]}"]
    if not text.strip():
        return ["[INFO] No observado (empty_ai)"]
    lines = [l.strip("•- \t") for l in text.splitlines() if l.strip()]
    out = [l[:240] for l in lines if len(l) >= 3]
    return out[:12] if out else ["[INFO] No observado (unparsed_ai)"]


def make_ai_prompt(snapshot: Snapshot) -> str:
    # Interpretación únicamente: todo viene de outputs ya recolectados
    return f"""
Input (no inventar, no suposiciones):
domain={snapshot.domain}
dns={snapshot.dns}
ip_primary={snapshot.ip_primary}
owner={snapshot.owner}
open_ports={snapshot.open_ports}
http_status={snapshot.http_status}
https_status={snapshot.https_status}
headers={snapshot.headers}
sec_headers_score={snapshot.sec_headers_score}
sec_headers_findings={snapshot.sec_headers_findings}
tls_not_after={snapshot.tls_not_after}
tls_versions={snapshot.tls_versions}
cdn_signals={snapshot.cdn_signals}
methods_flags={snapshot.methods_flags}
rate_limit={snapshot.rate_limit}
sensitive_hits={snapshot.sensitive_hits}
ip_direct_findings={snapshot.ip_direct_findings}
wafw00f={snapshot.wafw00f[:600]}
whatweb={snapshot.whatweb[:600]}

Output:
- 10 bullets técnicos, ultra cortos.
- Prefijo severidad: [CRIT]/[HIGH]/[MED]/[LOW]/[INFO]
- No relleno, no marketing.
- Si evidencia insuficiente: "No observado".
""".strip()


# -----------------------
# Heuristics bullets (sin AI)
# -----------------------
def heuristic_bullets(s: Snapshot) -> List[str]:
    b: List[str] = []

    # Basic
    if s.ip_primary in ("", "N/A"):
        b.append("[HIGH] DNS A: No observado")
    if s.https_status.startswith("ssl_error"):
        b.append("[HIGH] HTTPS TLS handshake error")
    if s.sec_headers_score <= 2:
        b.append(f"[HIGH] SecHeaders score={s.sec_headers_score}/6")
    elif s.sec_headers_score <= 4:
        b.append(f"[MED] SecHeaders score={s.sec_headers_score}/6")
    else:
        b.append(f"[INFO] SecHeaders score={s.sec_headers_score}/6")

    for f in s.sec_headers_findings[:8]:
        # Missing headers: MED por defecto
        sev = "[MED]"
        if "MISS Strict-Transport-Security" in f:
            sev = "[HIGH]"
        b.append(f"{sev} {f}")

    # TLS legacy
    if s.tls_versions.get("TLSv1.0") == "on":
        b.append("[HIGH] TLSv1.0: ON")
    if s.tls_versions.get("TLSv1.1") == "on":
        b.append("[MED] TLSv1.1: ON")
    if s.tls_versions.get("TLSv1.2") == "off" and s.tls_versions.get("TLSv1.3") == "off":
        b.append("[CRIT] TLS modern: OFF")

    # Ports
    exposed = [p for p in s.open_ports if p in RISKY_PORTS]
    if exposed:
        b.append(f"[HIGH] Exposed infra ports={exposed}")
    if 80 in s.open_ports and 443 not in s.open_ports:
        b.append("[MED] HTTPS: No observado (443 closed)")

    # Sensitive paths
    if s.sensitive_hits:
        b.append(f"[HIGH] Sensitive hits={len(s.sensitive_hits)}")
        for hit in s.sensitive_hits[:10]:
            # 200 = peor
            sev = "[HIGH]" if hit.startswith("200") else "[MED]"
            b.append(f"{sev} {hit}")

    # Methods
    for m in s.methods_flags[:6]:
        if "ALLOW TRACE" in m or "ALLOW TRACK" in m:
            b.append(f"[HIGH] {m}")
        elif "ALLOW PUT" in m or "ALLOW DELETE" in m:
            b.append(f"[MED] {m}")
        else:
            b.append(f"[INFO] {m}")

    # Rate-limit signals
    if s.rate_limit:
        last = s.rate_limit.get("last", "N/A")
        counts = s.rate_limit.get("counts", "{}")
        if last in ("429", "403"):
            b.append(f"[INFO] RateLimit last={last} counts={counts}")
        else:
            b.append(f"[LOW] RateLimit last={last} counts={counts}")

    # CDN/IP direct
    if s.cdn_signals:
        b.append(f"[INFO] CDN signals={len(s.cdn_signals)}")
        for sig in s.cdn_signals[:5]:
            b.append(f"[INFO] {sig}")
    if s.ip_direct_findings:
        b.append("[MED] IP-direct (Host header) responded")
        for it in s.ip_direct_findings[:3]:
            b.append(f"[MED] {it}")

    # Fingerprint presence (not details)
    if s.wafw00f and "missing_tool" not in s.wafw00f and s.wafw00f != "skip":
        b.append("[INFO] wafw00f: observed")
    if s.whatweb and "missing_tool" not in s.whatweb and s.whatweb != "skip":
        b.append("[INFO] whatweb: observed")

    return b


# -----------------------
# Main scan (single pass)
# -----------------------
def run_scan(domain: str, ports: List[int], verify_tls: bool, aggressive: bool, workers: int, rl_n: int) -> Snapshot:
    dns = resolve_dns(domain)
    ip_primary = (dns.get("A") or ["N/A"])[0]
    owner = whois_owner(ip_primary) if ip_primary not in ("", "N/A") else "N/A"

    open_ports = scan_ports(domain, ports, workers=workers)

    r_http, e_http = http_fetch(domain, "http", verify_tls=verify_tls)
    r_https, e_https = http_fetch(domain, "https", verify_tls=verify_tls)

    headers_raw = dict(r_https.headers) if r_https is not None else {}
    # limit keys (reduce prompt size)
    headers = {k: str(headers_raw.get(k, ""))[:200] for k in list(headers_raw.keys())[:70]}

    http_status = str(r_http.status_code) if r_http is not None else (e_http or "N/A")
    https_status = str(r_https.status_code) if r_https is not None else (e_https or "N/A")

    not_after = tls_not_after(domain) if (443 in open_ports or 443 in ports) else "N/A"
    tls_versions = tls_probe_versions(domain) if (443 in open_ports or 443 in ports) else {"TLS": "N/A"}

    sec_score, sec_findings = headers_audit(headers)

    methods_flags = methods_probe(domain, verify_tls=verify_tls) if aggressive else []
    rate_limit = rate_limit_probe(domain, verify_tls=verify_tls, n=rl_n) if aggressive else {}
    sensitive_hits = sensitive_paths_probe(domain, verify_tls=verify_tls) if aggressive else []
    cdn_signals = detect_cdn_signals(headers)
    ip_direct_findings = ip_direct_probe(domain, dns.get("A", [])) if aggressive else []

    wafw00f_out = waf_fingerprint(domain) if aggressive else "skip"
    whatweb_out = whatweb_fingerprint(domain) if aggressive else "skip"

    return Snapshot(
        domain=domain,
        dns=dns,
        ip_primary=ip_primary or "N/A",
        owner=owner,
        open_ports=open_ports,
        tls_not_after=not_after,
        tls_versions=tls_versions,
        http_status=http_status,
        https_status=https_status,
        headers=headers,
        sec_headers_score=sec_score,
        sec_headers_findings=sec_findings,
        cdn_signals=cdn_signals,
        methods_flags=methods_flags,
        rate_limit=rate_limit,
        sensitive_hits=sensitive_hits,
        ip_direct_findings=ip_direct_findings,
        wafw00f=wafw00f_out,
        whatweb=whatweb_out,
    )


# -----------------------
# UI
# -----------------------
st.title("🛡️ EdgeSight SE :: Light PT (Preventa técnico)")

c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
with c1:
    raw = st.text_input("Dominio", placeholder="empresa.com", label_visibility="collapsed")
with c2:
    verify_tls = not st.checkbox("No verificar TLS (inseguro)", value=False)
with c3:
    aggressive = st.checkbox("Modo agresivo", value=True)
with c4:
    ai_on = st.checkbox("AI bullets", value=True)

with st.expander("Scan profile", expanded=False):
    ports = st.multiselect("Puertos", TOP100_WEB_INFRA, default=TOP100_WEB_INFRA)
    workers = st.slider("Concurrencia", 16, 128, 64, 16)
    rl_n = st.slider("Rate-limit probe (requests)", 10, 60, 25, 5)

run_btn = st.button("🚀 Run", type="primary")

# session_state: evita reruns rehaciendo y re-llamando AI
if "last_snapshot" not in st.session_state:
    st.session_state.last_snapshot = None
if "last_bullets" not in st.session_state:
    st.session_state.last_bullets = None
if "last_snap_key" not in st.session_state:
    st.session_state.last_snap_key = None

if run_btn:
    dom = normalize_domain(raw)
    if not dom:
        st.error("Dominio inválido (ej: empresa.com)")
        st.stop()

    with st.status("Recon…", expanded=True) as status:
        status.write("Collect…")
        snap = run_scan(dom, ports, verify_tls, aggressive, workers, rl_n)
        status.update(label="Collect done", state="complete", expanded=False)

    # Heuristics siempre
    bullets = heuristic_bullets(snap)

    # AI: single call per snapshot, cached + guarded
    if ai_on:
        if CLIENT is None or MODEL_ID is None:
            bullets = (["[INFO] gemini_unavailable"] if GEMINI_ERR else ["[INFO] gemini_unavailable"]) + bullets
        else:
            k = snapshot_key(snap)
            prompt = make_ai_prompt(snap)
            # cache_data ya evita repeticiones por mismo snap_key
            ai_bul = cached_ai_bullets(MODEL_ID, k, prompt)
            bullets = ai_bul + bullets

            # persistir en session_state
            st.session_state.last_snap_key = k
    else:
        st.session_state.last_snap_key = snapshot_key(snap)

    st.session_state.last_snapshot = snap
    st.session_state.last_bullets = bullets

# Mostrar último resultado (aunque haya rerun)
snap: Optional[Snapshot] = st.session_state.last_snapshot
bullets: Optional[List[str]] = st.session_state.last_bullets

if snap and bullets:
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("IP", snap.ip_primary, snap.owner[:22] if snap.owner else "")
    m2.metric("HTTP", snap.http_status)
    m3.metric("HTTPS", snap.https_status)
    m4.metric("Ports open", len(snap.open_ports))
    m5.metric("SecHeaders", f"{snap.sec_headers_score}/6")

    st.markdown("---")
    left, right = st.columns([2, 1])

    with left:
        st.subheader("Alerts / Bullets")
        for b in bullets[:50]:
            if b.startswith("[CRIT]") or b.startswith("[HIGH]"):
                st.error(b)
            elif b.startswith("[MED]"):
                st.warning(b)
            else:
                st.info(b)

    with right:
        st.subheader("Raw (short)")
        st.write(f"**DNS A:** `{snap.dns.get('A', [])}`")
        st.write(f"**DNS AAAA:** `{snap.dns.get('AAAA', [])}`")
        st.write(f"**CNAME:** `{snap.dns.get('CNAME', [])}`")
        st.write(f"**MX:** `{snap.dns.get('MX', [])}`")
        st.write(f"**TLS notAfter:** `{snap.tls_not_after}`")
        st.write(f"**TLS versions:** `{snap.tls_versions}`")
        st.write(f"**Open ports:** `{snap.open_ports}`")
        st.write("**Headers:**")
        st.json(snap.headers)

        with st.expander("Fingerprint outputs", expanded=False):
            st.write("wafw00f")
            st.code((snap.wafw00f or "N/A")[:2500])
            st.write("whatweb")
            st.code((snap.whatweb or "N/A")[:2500])

        with st.expander("Snapshot JSON", expanded=False):
            st.code(json.dumps(asdict(snap), indent=2, default=str)[:12000])

    st.markdown("---")
    st.subheader("Export")
    pdf_bytes = build_pdf(snap, bullets)
    st.download_button("📥 PDF", data=pdf_bytes, file_name=f"{snap.domain}-lightpt.pdf", mime="application/pdf")

    st.subheader("Next actions (dry)")
    exposed = [p for p in snap.open_ports if p in RISKY_PORTS]
    nexts: List[str] = []
    if snap.sec_headers_score < 5:
        nexts.append("- Harden security headers (HSTS/CSP/XFO/XCTO/RP/PP)")
    if snap.tls_versions.get("TLSv1.0") == "on" or snap.tls_versions.get("TLSv1.1") == "on":
        nexts.append("- Disable legacy TLS (1.0/1.1), enforce modern policies")
    if exposed:
        nexts.append(f"- Close/segment exposed infra ports: {exposed}")
    if snap.ip_direct_findings:
        nexts.append("- Validate origin protection (ACL/mTLS/auth), prevent CDN bypass")
    if snap.sensitive_hits:
        nexts.append("- Remove/protect sensitive endpoints & backups")
    if not nexts:
        nexts.append("- Extend: CT subdomains + authz-driven tests (with approval)")
    st.code("\n".join(nexts))
else:
    st.caption("Ready.")
