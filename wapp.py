import streamlit as st
import subprocess
from google import genai
import shutil
import requests
import socket
import ssl
import re

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="NinjaZight SE", layout="wide")

@st.cache_resource
def boot():
    try:
        # Se asume GEMINI_API_KEY configurada en Secrets
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot()

# --- MOTOR DE RECONOCIMIENTO ---
def get_infra_data(domain):
    data = {
        "ip": "N/A", 
        "owner": "N/A", 
        "network": "N/A", 
        "asn": "N/A",
        "ssl_cn": "N/A", 
        "ssl_exp": "N/A", 
        "ports": [], 
        "whois_raw": ""
    }
    
    # 1. Resolución DNS Robusta (Sigue CNAME hasta obtener la IP final)
    try:
        res_dns = subprocess.run(["dig", domain, "A", "+short"], capture_output=True, text=True, timeout=5)
        lines = res_dns.stdout.splitlines()
        ips = [l for l in lines if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", l)]
        
        if ips:
            data["ip"] = ips[-1] # Selecciona la IP final de la cadena
            
            # 2. WHOIS sobre la IP encontrada
            res_w = subprocess.run(["whois", data["ip"]], capture_output=True, text=True, timeout=5)
            data["whois_raw"] = res_w.stdout
            
            for line in res_w.stdout.splitlines():
                line_l = line.lower()
                # Extrae Dueño (Organization/Descr)
                if any(x in line_l for x in ["org-name", "descr", "organization", "netname"]):
                    if ":" in line: data["owner"] = line.split(":", 1)[1].strip()
                # Extrae Rango de Red (CIDR)
                if "cidr" in line_l:
                    if ":" in line: data["network"] = line.split(":", 1)[1].strip()
                # Extrae ASN
                if "origin" in line_l or "aut-num" in line_l:
                    if ":" in line: data["asn"] = line.split(":", 1)[1].strip()
    except Exception:
        try: data["ip"] = socket.gethostbyname(domain)
        except: pass

    # 3. Certificado (CN y Expiración)
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
st.title("🛡️ NinjaZight SE")
target = st.text_input("Dominio:", placeholder="empresa.com", label_visibility="collapsed")

if st.button("🚀 Iniciar Auditoría"):
    if target:
        dom = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Analizando...", expanded=False) as status:
            infra = get_infra_data(dom)
            waf_raw = subprocess.run(["wafw00f", dom], capture_output=True, text=True).stdout or ""
            
            try:
                r = requests.get(f"https://{dom}", timeout=5, verify=False)
                srv = r.headers.get("Server", "Desconocido")
                cdn = r.headers.get("X-Cache", r.headers.get("CF-Cache-Status", "N/A"))
                h_ok = all(x in r.headers for x in ["Strict-Transport-Security", "Content-Security-Policy"])
            except: srv, cdn, h_ok = "N/A", "N/A", False

            prompt = f"Dom: {dom}, IP: {infra['ip']} ({infra['owner']}), Red: {infra['network']}, ASN: {infra['asn']}, CN: {infra['ssl_cn']}, SSL Exp: {infra['ssl_exp']}, Ports: {infra['ports']}, WAF: {waf_raw[:150]}, Srv: {srv}, CDN: {cdn}, SecHeaders: {h_ok}. Analiza anomalías y oportunidad Akamai en 5 bullets secos."
            res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
            status.update(label="Análisis Finalizado", state="complete")

        # --- Dashboard ---
        c1, c2, c3 = st.columns(3)
        c1.metric("IP Pública", infra['ip'], f"{infra['owner'][:20]} ({infra['asn']})")
        c2.metric("Certificado (CN)", infra['ssl_cn'][:30])
        c3.metric("Vencimiento SSL", infra['ssl_exp'][:15])

        c1b, c2b, c3b = st.columns(3)
        c1b.metric("Web Server", srv[:20])
        c2b.metric("CDN / WAF", "Detectado" if "is behind" in waf_raw or cdn != "N/A" else "None")
        c3b.metric("Security Headers", "✅ OK" if h_ok else "❌ Missing")

        st.divider()

        # --- Pestañas ---
        tab_brief, tab_tech = st.tabs(["⚡ Briefing Estratégico", "🛠️ Detalle Técnico"])
        
        with tab_brief:
            st.info(res.text)
            
        with tab_tech:
            st.json({
                "ip_resolucion": infra['ip'],
                "red_cidr": infra['network'],
                "asn": infra['asn'],
                "proveedor": infra['owner'],
                "common_name": infra['ssl_cn'],
                "puertos": infra['ports'],
                "servidor": srv
            })
            if infra["whois_raw"]:
                with st.expander("Ver WHOIS Completo"):
                    st.code(infra["whois_raw"])
