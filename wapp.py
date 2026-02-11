import streamlit as st
import subprocess
from google import genai
import shutil
import requests
import socket
import ssl
import re

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="EdgeSight SE", layout="wide")

@st.cache_resource
def boot():
    try:
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot()

# --- MOTOR DE RECONOCIMIENTO ---
def get_infra_data(domain):
    data = {"ip": "N/A", "owner": "N/A", "ssl_cn": "N/A", "ssl_exp": "N/A", "ports": []}
    
    # 1. IP Pública (Múltiples fallbacks)
    try:
        # Intento con dig (instalar dnsutils si falla)
        res_ip = subprocess.run(["dig", "+short", domain], capture_output=True, text=True, timeout=5)
        ip_list = [line for line in res_ip.stdout.splitlines() if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line)]
        if ip_list:
            data["ip"] = ip_list[0]
        else:
            data["ip"] = socket.gethostbyname(domain)
        
        # 2. Owner vía WHOIS
        res_w = subprocess.run(["whois", data["ip"]], capture_output=True, text=True, timeout=5)
        for line in res_w.stdout.splitlines():
            if any(x in line.lower() for x in ["org-name", "descr", "organization", "netname"]):
                data["owner"] = line.split(":", 1)[1].strip()
                break
    except: pass

    # 3. Certificado (OpenSSL style nativo)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                data["ssl_cn"] = subject.get('commonName', 'N/A')
                data["ssl_exp"] = cert.get('notAfter', 'N/A')
    except: pass

    # 4. Puertos
    for p in [80, 443, 8080, 8443, 2083]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex((domain, p)) == 0: data["ports"].append(p)
    
    return data

# --- INTERFAZ ---
st.title("🛡️ EdgeSight SE")
target = st.text_input("Dominio:", placeholder="empresa.com", label_visibility="collapsed")

if st.button("🚀 Iniciar Auditoría"):
    if target:
        dom = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Ejecutando...", expanded=False) as status:
            infra = get_infra_data(dom)
            waf_raw = subprocess.run(["wafw00f", dom], capture_output=True, text=True).stdout or ""
            
            # Análisis de cabeceras
            try:
                r = requests.get(f"https://{dom}", timeout=5, verify=False)
                srv = r.headers.get("Server", "Desconocido")
                cdn = r.headers.get("X-Cache", r.headers.get("CF-Cache-Status", "N/A"))
                h_ok = all(x in r.headers for x in ["Strict-Transport-Security", "Content-Security-Policy"])
            except: srv, cdn, h_ok = "N/A", "N/A", False

            # Prompt imperativo para brevedad extrema
            prompt = f"Dom: {dom}, IP: {infra['ip']}, CN: {infra['ssl_cn']}, Exp: {infra['ssl_exp']}, Ports: {infra['ports']}, WAF: {waf_raw[:150]}, Srv: {srv}, CDN: {cdn}, SecHeaders: {h_ok}. Analiza anomalías técnicas para venta Akamai en 5 puntos secos."
            res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
            status.update(label="Análisis Finalizado", state="complete")

        # --- Dashboard de Métricas (Principal) ---
        c1, c2, c3 = st.columns(3)
        c1.metric("IP Pública", infra['ip'], infra['owner'][:25])
        c2.metric("Certificado (CN)", infra['ssl_cn'][:30])
        c3.metric("Vencimiento SSL", infra['ssl_exp'][:15])

        c1b, c2b, c3b = st.columns(3)
        c1b.metric("Web Server", srv[:20])
        c2b.metric("CDN / WAF", "Detectado" if "is behind" in waf_raw or cdn != "N/A" else "None")
        c3b.metric("Security Headers", "✅ OK" if h_ok else "❌ Missing")

        st.divider()

        # --- Pestañas para ocultar detalle ---
        tab_brief, tab_tech = st.tabs(["⚡ Briefing Estratégico", "🛠️ Detalle Técnico (Oculto)"])
        
        with tab_brief:
            st.info(res.text)
            
        with tab_tech:
            st.code(f"""
IP: {infra['ip']}
OWNER: {infra['owner']}
COMMON NAME: {infra['ssl_cn']}
EXPIRATION: {infra['ssl_exp']}
PORTS OPEN: {infra['ports']}
SERVER HEADER: {srv}
CDN/WAF HEADER: {cdn}
            """)
            st.write("**Salida Cruta de Herramientas:**")
            st.text(waf_raw[:1000])
