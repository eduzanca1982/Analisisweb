import streamlit as st
import socket
import ssl
import requests
import datetime
import subprocess
import re
import json

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide")
st.title("Scan Apukay EZ - WAF / CDN / TLS / WHOIS")

API_KEY = st.secrets.get("GOOGLE_API_KEY")

# ===============================
# NETWORK SNAPSHOT
# ===============================

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return "N/A"

def get_headers(url):
    try:
        r = requests.get(url, timeout=10)
        return dict(r.headers)
    except:
        return {}

def detect_waf(headers):
    h = str(headers).lower()
    if "akamai" in h:
        return "Akamai"
    if "cloudflare" in h:
        return "Cloudflare"
    if "sucuri" in h:
        return "Sucuri"
    if "imperva" in h:
        return "Imperva"
    return "No evidente"

def get_tls_info(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            not_after = cert['notAfter']
            expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days
            return {
                "issuer": dict(x[0] for x in cert['issuer']).get("organizationName"),
                "not_after": not_after,
                "days_left": days_left,
                "tls_version": s.version()
            }
    except Exception as e:
        return {"error": str(e)}

def whois_ip(ip):
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=8)
        data = result.stdout
        org = re.search(r"OrgName:\s*(.*)", data)
        netname = re.search(r"NetName:\s*(.*)", data)
        country = re.search(r"Country:\s*(.*)", data)
        return {
            "org": org.group(1) if org else None,
            "netname": netname.group(1) if netname else None,
            "country": country.group(1) if country else None
        }
    except:
        return {}

# ===============================
# IA OBSERVACIONES
# ===============================

def ai_analysis(snapshot):
    if not API_KEY:
        return "No API KEY configurada"

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=API_KEY,
        temperature=0
    )

    prompt = f"""
Analiza este snapshot técnico de un sitio web.
Devuelve SOLO bullets técnicos (sin introducción).

Datos:
{json.dumps(snapshot, indent=2)}
"""

    return llm.invoke([HumanMessage(content=prompt)]).content

# ===============================
# UI
# ===============================

target = st.text_input("Target (sin https://)", placeholder="example.com")

if st.button("Analizar") and target:

    with st.spinner("Resolviendo..."):

        ip = resolve_ip(target)
        headers = get_headers(f"https://{target}")
        waf = detect_waf(headers)
        tls = get_tls_info(target)
        whois = whois_ip(ip)

        snapshot = {
            "host": target,
            "ip": ip,
            "waf_cdn_detected": waf,
            "tls": tls,
            "whois": whois,
            "headers": headers
        }

    # ===============================
    # SNAPSHOT VISUAL SUPERIOR
    # ===============================

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IP", ip)
    c2.metric("WAF/CDN", waf)
    c3.metric("Cert Days Left", tls.get("days_left") if isinstance(tls, dict) else "N/A")
    c4.metric("TLS", tls.get("tls_version") if isinstance(tls, dict) else "N/A")

    st.divider()

    # ===============================
    # OUTPUT CRUDO
    # ===============================

    colA, colB = st.columns(2)

    with colA:
        st.subheader("TLS / Certificado")
        st.json(tls)

        st.subheader("WHOIS")
        st.json(whois)

    with colB:
        st.subheader("Headers")
        st.json(headers)

    st.divider()

    # ===============================
    # IA
    # ===============================

    st.subheader("Observaciones IA")

    try:
        bullets = ai_analysis(snapshot)
        st.markdown(bullets)
    except Exception as e:
        st.error(f"Error IA: {e}")
