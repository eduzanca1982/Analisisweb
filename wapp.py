import streamlit as st
import socket
import ssl
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
# ENGINE DE DETECCIÓN AGRESIVA
# ===============================

def get_raw_edge_data(host):
    """Obtiene headers y banners mediante socket para evitar bloqueos de nivel de aplicación."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Request minimalista para forzar respuesta de headers
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode())
                response = ssock.recv(4096).decode('utf-8', errors='ignore')
                headers = {}
                for line in response.split('\r\n')[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k] = v
                return headers, ssock.version()
    except:
        return {}, "N/A"

def fingerprint_infrastructure(headers):
    """Detecta proveedores mediante firmas de headers."""
    h_str = json.dumps(headers).lower()
    signatures = {
        "Akamai": ["akamai", "x-akamai", "edge-cache-tag"],
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "AWS CloudFront": ["x-amz-cf-", "cloudfront"],
        "Imperva": ["x-iinfo", "incap-ses", "visid_incap"],
        "Fastly": ["x-fastly", "fastly"]
    }
    found = [name for name, sigs in signatures.items() if any(s in h_str for s in sigs)]
    return ", ".join(found) if found else "No detectado"

def get_tls_details(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                issuer = dict(x[0] for x in cert['issuer']).get("organizationName")
                return {"issuer": issuer, "expiry": str(expiry), "days_left": days_left, "version": s.version()}
    except Exception as e:
        return {"error": str(e)}

def deep_whois(ip):
    """Comando whois agresivo para extraer parámetros de red."""
    try:
        res = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
        out = res.stdout
        patterns = {
            "Org": r"OrgName|Organization|owner",
            "NetName": r"NetName|network:name",
            "Range": r"NetRange|inetnum",
            "Route": r"route"
        }
        extracted = {}
        for key, p in patterns.items():
            match = re.search(f"({p}):\s*(.*)", out, re.IGNORECASE)
            extracted[key] = match.group(2).strip() if match else "N/A"
        return extracted
    except:
        return {"error": "Whois failed"}

# ===============================
# IA OBSERVACIONES
# ===============================

def ai_analysis(snapshot):
    if not API_KEY: return "Error: No API Key"
    
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=API_KEY, temperature=0)
    
    prompt = f"""
    Analiza este snapshot técnico. Detecta fallas de seguridad, discrepancias de IP/infraestructura y validez de certificados.
    FORMATO: Solo bullets técnicos. Sin introducciones.
    FOCO: Detectar WAF/CDN real, IP de origen probable (si aplica) y riesgos de vencimiento.

    DATOS:
    {json.dumps(snapshot, indent=2)}
    """
    return llm.invoke([HumanMessage(content=prompt)]).content

# ===============================
# UI STREAMLIT
# ===============================

target = st.text_input("Target Domain", placeholder="ejemplo.com")

if st.button("Ejecutar Análisis") and target:
    with st.spinner("Escaneando Edge..."):
        ip = socket.gethostbyname(target)
        headers, tls_ver = get_raw_edge_data(target)
        infra = fingerprint_infrastructure(headers)
        tls = get_tls_details(target)
        net_info = deep_whois(ip)

        snapshot = {
            "ip": ip,
            "detected_infra": infra,
            "tls_info": tls,
            "net_whois": net_info,
            "headers": headers
        }

        # Dashboard de métricas
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("IP Responde", ip)
        m2.metric("Infraestructura", infra)
        m3.metric("Días Cert", tls.get("days_left", "N/A"))
        m4.metric("Protocolo", tls.get("version", "N/A"))

        st.divider()

        # Layout de datos
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("Network & WHOIS")
            st.json(net_info)
            st.subheader("Certificado")
            st.json(tls)
        
        with col_right:
            st.subheader("IA Technical Insights")
            try:
                insights = ai_analysis(snapshot)
                st.markdown(insights)
            except Exception as e:
                st.error(f"Error en IA: {e}")
            
            with st.expander("Ver Raw Headers"):
                st.json(headers)
