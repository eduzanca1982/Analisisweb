import streamlit as st
import subprocess
from google import genai
import shutil
import requests
import socket
import ssl
from fpdf import FPDF

st.set_page_config(page_title="EdgeSight SE Edition", layout="wide", page_icon="⚡")

@st.cache_resource
def boot_gemini():
    try:
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot_gemini()

def scan_ports(domain):
    ports = [80, 443, 8080, 8443, 2082, 2083, 2086, 2087]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((domain, port)) == 0:
                    open_ports.append(port)
        except: pass
    return open_ports

def analyze_security_headers(headers):
    checks = {
        "HSTS": "Strict-Transport-Security" in headers,
        "CSP": "Content-Security-Policy" in headers,
        "X-Frame": "X-Frame-Options" in headers,
        "X-Content-Type": "X-Content-Type-Options" in headers,
        "Referrer-Policy": "Referrer-Policy" in headers
    }
    return checks

def get_network_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
        owner = "Desconocido"
        for line in res.stdout.splitlines():
            line_l = line.lower()
            if any(k in line_l for k in ["org-name", "organization", "descr"]):
                owner = line.split(":", 1)[1].strip()
                break
        return ip, owner
    except: return "N/A", "N/A"

st.title("🛡️ EdgeSight: SE Intelligence Console")

target = st.text_input("Dominio del cliente:", placeholder="ejemplo.com")

if st.button("🚀 Ejecutar Auditoría"):
    if target:
        dom = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Procesando inteligencia de infraestructura...", expanded=True):
            ip, owner = get_network_info(dom)
            
            headers_data = {}
            try:
                r = requests.get(f"https://{dom}", timeout=10, verify=False)
                headers_data = r.headers
                sec_checks = analyze_security_headers(headers_data)
            except:
                sec_checks = {k: False for k in ["HSTS", "CSP", "X-Frame", "X-Content-Type", "Referrer-Policy"]}

            waf = subprocess.run(["wafw00f", dom], capture_output=True, text=True).stdout or ""
            what = subprocess.run(["whatweb", dom], capture_output=True, text=True).stdout or ""
            ports = scan_ports(dom)

            prompt = f"""
            Analiza como Senior SE de Akamai: {dom}
            Infra: IP {ip} ({owner}), Puertos abiertos: {ports}
            WAF: {waf[:300]}
            WhatWeb: {what[:300]}
            Security Headers: {[k for k,v in sec_checks.items() if v]} (Missing: {[k for k,v in sec_checks.items() if not v]})
            Server: {headers_data.get('Server', 'Oculto')}

            Genera un informe visual de 5 bullets para un SE enfocado en anomalías técnicas y vectores de venta para Akamai. 
            Menciona si los puertos abiertos sugieren servicios administrativos expuestos.
            Sé directo, agnóstico de herramientas y técnico.
            """
            
            try:
                res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
                report = res.text
            except Exception as e:
                report = f"Error en procesamiento de inteligencia."

        c1, c2, c3 = st.columns(3)
        with c1: st.metric("IP Pública", ip, owner)
        with c2: st.metric("Postura de Headers", f"{sum(sec_checks.values())}/5")
        with c3: st.metric("Puertos Detectados", len(ports))

        st.markdown("---")
        st.subheader("📝 Briefing Técnico y Anomalías")
        st.info(report)

        col_p, col_h = st.columns(2)
        with col_p:
            st.write("**Servicios Expuestos (Puertos):**")
            st.write(f"`{', '.join(map(str, ports))}`" if ports else "Solo puertos estándar")
        
        with col_h:
            st.write("**Seguridad en Headers:**")
            h_status = " | ".join([f"{k} {'✅' if v else '❌'}" for k, v in sec_checks.items()])
            st.markdown(h_status)

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, f"SE Technical Report: {dom}", ln=1)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, report.encode('latin-1', 'replace').decode('latin-1'))
        st.download_button("📥 Descargar Reporte", data=bytes(pdf.output()), file_name=f"Intel_{dom}.pdf")
