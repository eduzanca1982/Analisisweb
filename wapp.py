import streamlit as st
import subprocess
import socket
import json
import ssl
import datetime
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide")

# Estilo minimalista personalizado
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
    """, unsafe_allow_html=True)

st.title("Scan Apukay EZ - Infraestructura")

def get_cert_info(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert['notAfter']
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                issuer = dict(x[0] for x in cert['issuer']).get("organizationName")
                return {"expiry": expiry.strftime("%Y-%m-%d"), "days": days_left, "issuer": issuer}
    except:
        return {"expiry": "N/A", "days": "N/A", "issuer": "N/A"}

def get_engine_analysis(raw_data):
    try:
        api_key = st.secrets.get("GEMINI_API_KEY")
        if not api_key: return "Error: Configurar GEMINI_API_KEY."
        
        engine = ChatGoogleGenerativeAI(model="gemini-2.0-flash", google_api_key=api_key, temperature=0)
        prompt = f"Analizá este volcado técnico. Identificá WAF/CDN, red y seguridad. Solo bullets técnicos directos:\n{raw_data}"
        return engine.invoke([HumanMessage(content=prompt)]).content
    except Exception as e:
        return f"Error en el motor: {str(e)}"

target = st.text_input("Target Domain", placeholder="ejemplo.com.py")

if st.button("Ejecutar Análisis") and target:
    with st.spinner("Analizando bordes..."):
        # Recolección de datos
        ip = socket.gethostbyname(target)
        cert = get_cert_info(target)
        
        # Comandos de sistema
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True)

        # Dashboard de métricas superior
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("IP Responde", ip)
        col2.metric("Emisor Cert", cert['issuer'])
        col3.metric("Días Vencimiento", cert['days'], delta_color="inverse" if cert['days'] != "N/A" and cert['days'] < 30 else "normal")
        col4.metric("Fecha Cert", cert['expiry'])

        st.divider()

        # Consolidación para motor
        audit_data = {
            "ip": ip, "cert": cert,
            "waf_raw": w_proc.stdout,
            "tech_raw": ww_proc.stdout,
            "whois_raw": whois_proc.stdout
        }

        # Layout de resultados
        c_left, c_right = st.columns([1, 1])
        
        with c_left:
            st.subheader("Resultados de Infraestructura")
            st.markdown(get_engine_analysis(json.dumps(audit_data)))

        with c_right:
            with st.expander("Ver RAW Outputs (WhatWeb / WHOIS)"):
                st.code(ww_proc.stdout)
                st.code(whois_proc.stdout)
