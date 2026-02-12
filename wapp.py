import streamlit as st
import subprocess
import socket
import json
import ssl
import datetime
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide", initial_sidebar_state="collapsed")

# Custom CSS para estética Dark Tech
st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] { background-color: #050505; }
    .stMetric { 
        background-color: #111; 
        border: 1px solid #333; 
        padding: 20px; 
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .status-card {
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #00ff41;
        background-color: #161b22;
        margin-bottom: 20px;
    }
    h1, h2, h3 { color: #e6edf3 !important; font-family: 'Courier New', monospace; }
    </style>
    """, unsafe_allow_html=True)

def get_cert_details(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert['notAfter']
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                return {"expiry": expiry.strftime("%Y-%m-%d"), "days": days_left, "issuer": dict(x[0] for x in cert['issuer']).get("organizationName")}
    except:
        return {"expiry": "N/A", "days": 0, "issuer": "N/A"}

def engine_audit(raw_blob):
    try:
        api_key = st.secrets.get("GEMINI_API_KEY")
        engine = ChatGoogleGenerativeAI(model="gemini-2.0-flash", google_api_key=api_key, temperature=0)
        
        prompt = f"""
        Sos un auditor de infraestructura senior. Analizá el volcado adjunto con foco crítico en:
        1. Identificación precisa de CDN y WAF (Imperva, Akamai, Cloudflare, etc.).
        2. Análisis de headers de seguridad ausentes o mal configurados.
        3. Verificación de propiedad de la red vía WHOIS.
        
        FORMATO: Solo bullets técnicos cortos y agresivos.
        DUMP: {raw_blob}
        """
        return engine.invoke([HumanMessage(content=prompt)]).content
    except Exception as e:
        return f"Error en motor: {str(e)}"

# UI Principal
st.title("🛡️ SCAN APUKAY EZ")
st.markdown("### Edge Infrastructure Insights")

target = st.text_input("Ingresar Dominio", placeholder="ejemplo.com.py", help="Analizar bordes, certificados y capas de seguridad.")

if st.button("INICIAR AUDITORÍA") and target:
    with st.spinner("Escaneando capas de red..."):
        # Datos Base
        ip = socket.gethostbyname(target)
        cert = get_cert_details(target)
        
        # Ejecución de comandos de sistema
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True)

        # Header de Métricas Rápidas
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("HOST IP", ip)
        m2.metric("SSL ISSUER", cert['issuer'])
        m3.metric("EXPIRACIÓN", f"{cert['days']} días", delta=f"{cert['days']}d")
        m4.metric("FECHA CERT", cert['expiry'])

        st.markdown("---")

        # Layout Principal: Análisis de Borde
        col_main, col_side = st.columns([2, 1])

        with col_main:
            st.markdown("#### 🔍 Análisis de Borde (CDN/WAF)")
            # Consolidamos datos para la IA
            audit_dump = {
                "ip": ip, "cert": cert,
                "wafw00f": w_proc.stdout,
                "whatweb": ww_proc.stdout,
                "whois": whois_proc.stdout
            }
            
            # Resultado del motor técnico
            analysis = engine_audit(json.dumps(audit_dump))
            st.info(analysis)

        with col_side:
            st.markdown("#### 📦 Tech Stack & WHOIS")
            with st.expander("Fingerprint de Servidor"):
                st.code(ww_proc.stdout, language="text")
            with st.expander("Registro de Red (WHOIS)"):
                st.code(whois_proc.stdout, language="text")
            
            # Alerta rápida basada en detección de red
            if "incapsula" in whois_proc.stdout.lower() or "imperva" in whois_proc.stdout.lower():
                st.success("✅ Estructura protegida por IMPERVA detectada vía Red.")
            elif "akamai" in whois_proc.stdout.lower():
                st.success("✅ Estructura protegida por AKAMAI detectada vía Red.")
