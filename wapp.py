import streamlit as st
import subprocess
from google import genai
import shutil
import requests
import socket
import ssl
from datetime import datetime
from fpdf import FPDF

st.set_page_config(page_title="EdgeSight v2", layout="wide")

# --- BOOT & CONFIG ---
@st.cache_resource
def boot_gemini():
    try:
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot_gemini()

# --- FUNCIONES TÉCNICAS ---
def get_network_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        # WHOIS básico via comando
        whois = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=5).stdout
        owner = "Desconocido"
        for line in whois.splitlines():
            if "org-name" in line.lower() or "organization" in line.lower() or "descr" in line.lower():
                owner = line.split(":", 1)[1].strip()
                break
        return ip, owner, whois[:500] # Truncado para evitar errores de API
    except: return "N/A", "N/A", "N/A"

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName')
                org = subject.get('organizationName', 'N/A')
                expires = cert.get('notAfter')
                return {"cn": common_name, "org": org, "expiry": expires}
    except: return None

def get_http_intel(domain):
    data = {}
    for p in ["http", "https"]:
        try:
            r = requests.get(f"{p}://{domain}", timeout=5, verify=False)
            data[p] = {"srv": r.headers.get("Server", "?"), "cdn": r.headers.get("X-Cache", "N/A")}
        except: data[p] = "Error"
    return data

# --- INTERFAZ ---
st.title("🛡️ EdgeSight Intelligence")

target = st.text_input("Dominio:", placeholder="ejemplo.com")

if st.button("🚀 Escanear"):
    if target:
        dom = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Recolectando evidencia...", expanded=True):
            # Ejecución de herramientas
            waf = subprocess.run(["wafw00f", dom], capture_output=True, text=True).stdout
            what = subprocess.run(["whatweb", dom], capture_output=True, text=True).stdout
            ip, owner, whois_raw = get_network_info(dom)
            ssl_data = get_ssl_info(dom)
            http_data = get_http_intel(dom)

            # Prompt visual y ultra-conciso
            prompt = f"""
            Analiza como SE de Akamai: {dom}
            IP: {ip} ({owner}) | SSL: {ssl_data}
            WAF Log: {waf[:400]} | WhatWeb: {what[:400]} | Headers: {http_data}
            
            OUTPUT: Máximo 5 bullets. Formato:
            - **Infra**: [Servidor/CDN]
            - **WAF**: [Estado/Marca]
            - **SSL**: [CN y Vencimiento]
            - **Red**: [IP y Owner]
            - **Nota**: [Anomalía detectada o recomendación Akamai]
            Sin texto adicional.
            """
            
            try:
                res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
                report = res.text
            except Exception as e:
                report = "Error en IA: Intenta con un dominio menos complejo."

        # --- DASHBOARD VISUAL ---
        c1, c2, c3 = st.columns(3)
        with c1: st.metric("IP Pública", ip, owner)
        with c2: 
            if ssl_data: st.metric("SSL Expira", ssl_data['expiry'][:12])
        with c3:
            cdn_val = http_data.get("https", {}).get("cdn", "N/A") if isinstance(http_data.get("https"), dict) else "N/A"
            st.metric("CDN Detectado", cdn_val)

        st.markdown("---")
        st.subheader("⚡ Estrategia Flash")
        st.info(report)

        # Tablas técnicas
        with st.expander("Ver Auditoría Detallada"):
            st.table({
                "Protocolo": ["HTTP", "HTTPS"],
                "Servidor": [http_data['http'].get('srv') if isinstance(http_data['http'], dict) else "N/A", 
                             http_data['https'].get('srv') if isinstance(http_data['https'], dict) else "N/A"],
                "CDN/Cache": [http_data['http'].get('cdn') if isinstance(http_data['http'], dict) else "N/A", 
                              http_data['https'].get('cdn') if isinstance(http_data['https'], dict) else "N/A"]
            })
            if ssl_data:
                st.write(f"**Certificado:** {ssl_data['cn']} | **Organización:** {ssl_data['org']}")

        # PDF simple
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, f"Briefing: {dom}", ln=1)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, report.encode('latin-1', 'replace').decode('latin-1'))
        st.download_button("📥 Descargar PDF", data=bytes(pdf.output()), file_name=f"{dom}.pdf")
