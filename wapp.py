import streamlit as st
import subprocess
import socket
import json
import ssl
import datetime
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide", initial_sidebar_state="collapsed")

# CSS para estética Dark Tech y jerarquía visual
st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] { background-color: #050505; }
    .stMetric { 
        background-color: #0d1117; 
        border: 1px solid #30363d; 
        padding: 15px; 
        border-radius: 6px;
    }
    [data-testid="stMetricValue"] { font-size: 1.6rem !important; color: #58a6ff; }
    .main-header { font-family: 'Courier New', monospace; color: #e6edf3; border-bottom: 2px solid #238636; padding-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

def get_cert_details(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return {
                    "expiry": expiry.strftime("%Y-%m-%d"),
                    "days": (expiry - datetime.datetime.utcnow()).days,
                    "issuer": dict(x[0] for x in cert['issuer']).get("organizationName")
                }
    except: return {"expiry": "N/A", "days": 0, "issuer": "N/A"}

def run_analysis_engine(data):
    try:
        api_key = st.secrets.get("GEMINI_API_KEY")
        engine = ChatGoogleGenerativeAI(model="gemini-2.0-flash", google_api_key=api_key, temperature=0)
        prompt = f"Auditoría técnica de infraestructura. Identificá WAF/CDN y pertenencia de red (WHOIS). Solo bullets directos:\n{data}"
        return engine.invoke([HumanMessage(content=prompt)]).content
    except Exception as e: return f"Error motor: {str(e)}"

st.markdown("<h1 class='main-header'>🛡️ SCAN APUKAY EZ</h1>", unsafe_allow_html=True)

target = st.text_input("Target Domain", placeholder="ejemplo.com.py")

if st.button("INICIAR ESCANEO") and target:
    with st.spinner("Analizando bordes y red..."):
        # Ejecución técnica
        try:
            ip = socket.gethostbyname(target)
        except:
            ip = "Error IP"
            
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True) if ip != "Error IP" else type('obj', (object,), {'stdout': 'N/A'})
        cert = get_cert_details(target)

        # Extracción de WebServer desde WhatWeb
        server_match = [line for line in ww_proc.stdout.split(',') if 'Server[' in line]
        server_label = server_match[0].strip().replace("Server[", "").replace("]", "") if server_match else "No detectado"

        # FILA 1: INFRAESTRUCTURA DE BORDE (PRIMARIA)
        st.markdown("### 🌐 Capa de Infraestructura")
        r1_c1, r1_c2, r1_c3, r1_c4 = st.columns(4)
        
        # Lógica de detección rápida para UI
        full_output_lower = (w_proc.stdout + whois_proc.stdout).lower()
        waf_ui = "No detectado"
        if "incapsula" in full_output_lower or "imperva" in full_output_lower: waf_ui = "Imperva / Incapsula"
        elif "cloudflare" in full_output_lower: waf_ui = "Cloudflare"
        elif "akamai" in full_output_lower: waf_ui = "Akamai"
        
        r1_c1.metric("HOST IP", ip)
        r1_c2.metric("WAF / CDN", waf_ui)
        r1_c3.metric("WEB SERVER", server_label)
        r1_c4.metric("RED (WHOIS)", "Identificada" if "Error" not in ip else "N/A")

        # FILA 2: SEGURIDAD Y CERTIFICADOS (SECUNDARIA)
        st.markdown("### 🔐 Capa de Seguridad")
        r2_c1, r2_c2, r2_c3, r2_c4 = st.columns(4)
        r2_c1.metric("SSL EMISOR", cert['issuer'])
        r2_c2.metric("SSL VENCIMIENTO", cert['expiry'])
        r2_c3.metric("DÍAS RESTANTES", f"{cert['days']}d")
        r2_c4.metric("ESTADO", "Válido" if cert['days'] > 0 else "Expirado")

        st.divider()

        # ÁREA DE ANÁLISIS DINÁMICO
        c_left, c_right = st.columns([2, 1])
        
        with c_left:
            st.markdown("#### 📜 Análisis de Borde")
            # Unificación de la variable que causaba el NameError
            audit_data = {
                "ip": ip, 
                "waf": w_proc.stdout, 
                "tech": ww_proc.stdout, 
                "whois": whois_proc.stdout,
                "cert": cert
            }
            st.info(run_analysis_engine(json.dumps(audit_data)))

        with c_right:
            st.markdown("#### 🛠️ Raw Debug")
            with st.expander("Detalle WHOIS"):
                st.code(whois_proc.stdout)
            with st.expander("Detalle WhatWeb"):
                st.code(ww_proc.stdout)
