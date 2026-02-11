import streamlit as st
import subprocess
from google import genai
import shutil
import requests
import socket
import ssl

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="EdgeSight SE", layout="wide")

@st.cache_resource
def boot():
    try:
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot()

# --- MOTOR TÉCNICO ---
def get_infra_data(domain):
    data = {"ip": "N/A", "owner": "N/A", "ssl_exp": "N/A", "ports": [], "dnssec": False}
    # IP & Owner
    try:
        res_ip = subprocess.run(["dig", "+short", domain], capture_output=True, text=True, timeout=5)
        data["ip"] = res_ip.stdout.splitlines()[0] if res_ip.stdout else socket.gethostbyname(domain)
        res_w = subprocess.run(["whois", data["ip"]], capture_output=True, text=True, timeout=5)
        for line in res_w.stdout.splitlines():
            if any(x in line.lower() for x in ["org-name", "descr", "organization"]):
                data["owner"] = line.split(":", 1)[1].strip(); break
    except: pass

    # DNSSEC Check
    try:
        res_ds = subprocess.run(["dig", "+short", "DS", domain], capture_output=True, text=True, timeout=3)
        data["dnssec"] = True if res_ds.stdout.strip() else False
    except: pass

    # Puertos Críticos
    for p in [80, 443, 8080, 8443, 2083]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex((domain, p)) == 0: data["ports"].append(p)

    # Certificado
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                data["ssl_exp"] = cert.get('notAfter', 'N/A')
    except: pass
    
    return data

# --- INTERFAZ ---
st.title("🛡️ EdgeSight SE")
target = st.text_input("Dominio:", placeholder="empresa.com", label_visibility="collapsed")

if st.button("🚀 Iniciar Auditoría"):
    if target:
        dom = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Analizando...", expanded=False) as status:
            infra = get_infra_data(dom)
            waf = subprocess.run(["wafw00f", dom], capture_output=True, text=True).stdout or ""
            what = subprocess.run(["whatweb", dom], capture_output=True, text=True).stdout or ""
            
            try:
                r = requests.get(f"https://{dom}", timeout=5, verify=False)
                srv = r.headers.get("Server", "Desconocido")
                cdn = r.headers.get("X-Cache", r.headers.get("CF-Cache-Status", "N/A"))
                h_ok = all(x in r.headers for x in ["Strict-Transport-Security", "Content-Security-Policy"])
            except: srv, cdn, h_ok = "N/A", "N/A", False

            prompt = f"Dom: {dom}, IP: {infra['ip']} ({infra['owner']}), Ports: {infra['ports']}, DNSSEC: {infra['dnssec']}, WAF: {waf[:150]}, Srv: {srv}, CDN: {cdn}, SecHeaders: {h_ok}. Output: 5 bullets secos, anomalías y valor Akamai."
            res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
            status.update(label="Análisis Finalizado", state="complete")

        # Dashboard Minimalista
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IP Pública", infra['ip'], infra['owner'][:20])
        c2.metric("DNSSEC", "Activo" if infra['dnssec'] else "Inexistente")
        c3.metric("Security Headers", "✅ OK" if h_ok else "❌ Missing")
        c4.metric("Puertos", len(infra['ports']))

        st.divider()

        # Resumen Técnico
        col_a, col_b = st.columns([2, 1])
        with col_a:
            st.info(res.text)
        with col_b:
            st.code(f"""
SERVER: {srv}
CDN/WAF: {cdn}
PORTS: {infra['ports']}
SSL EXP: {infra['ssl_exp'][:15]}
            """)
