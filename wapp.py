import streamlit as st
import subprocess
import google.generativeai as genai
import shutil
import requests
from fpdf import FPDF
import base64

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="EdgeSight | Akamai Technical Sales", layout="wide", page_icon="🛡️")

# --- LÓGICA DE PDF ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Akamai Prospect Intelligence Report', 0, 1, 'C')
        self.ln(5)

def create_download_link(text, filename):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)
    # Limpieza de caracteres para el PDF
    clean_text = text.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 10, txt=clean_text)
    html = pdf.output(dest="S")
    b64 = base64.b64encode(html.encode('latin-1')).decode()
    return f'<a href="data:application/pdf;base64,{b64}" download="{filename}.pdf">📥 Descargar Reporte PDF</a>'

# --- API GEMINI ---
GEMINI_API_KEY = st.sidebar.text_input("Gemini API Key", type="password")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')

# --- FUNCIONES TÉCNICAS ADICIONALES ---
def get_security_headers(url):
    """Analiza encabezados de seguridad críticos."""
    try:
        if not url.startswith('http'): url = 'https://' + url
        response = requests.get(url, timeout=10)
        h = response.headers
        analysis = {
            "HSTS": "Strict-Transport-Security" in h,
            "CSP": "Content-Security-Policy" in h,
            "X-Frame": "X-Frame-Options" in h,
            "Server": h.get("Server", "No expuesto")
        }
        return analysis
    except:
        return None

def run_command(cmd_list):
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no instalado."
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=45)
        return result.stdout
    except Exception as e:
        return str(e)

# --- INTERFAZ ---
st.title("🛡️ EdgeSight: Prospección Técnica Akamai")

target = st.text_input("Dominio del cliente (ej: empresa.com):")

if st.button("Ejecutar Análisis Full"):
    if not GEMINI_API_KEY:
        st.error("Ingresa la API Key en la barra lateral.")
    elif target:
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🛠️ Procesando auditoría multinivel...", expanded=True) as status:
            # 1. Herramientas Externas
            st.write("Detectando WAF y CDN...")
            waf_out = run_command(["w00fwaf", clean_target])
            whatweb_out = run_command(["whatweb", "--aggression", "1", clean_target])
            
            # 2. Análisis Técnico Propio (Headers)
            st.write("Verificando encabezados de seguridad...")
            headers_info = get_security_headers(clean_target)
            
            # 3. Inteligencia Artificial
            st.write("Generando estrategia comercial...")
            contexto = f"""
            Dominio: {clean_target}
            WhatWeb: {whatweb_out}
            WAF Detection: {waf_out}
            Security Headers: {headers_info}
            """
            
            prompt = f"""
            Eres un Solution Engineer de Akamai. Analiza estos datos para una venta estratégica:
            1. Infraestructura: ¿Qué usan hoy?
            2. Brechas Técnicas: ¿Tienen HSTS o CSP? ¿El servidor expone versión?
            3. Argumento Akamai: Si no tienen WAF o usan competencia (Cloudflare/AWS), ¿cómo ayuda Akamai App & API Protector? 
            4. Performance: ¿Hay signos de que necesiten Ion o Image & Video Manager?
            Responde de forma ejecutiva.
            """
            
            ai_report = model.generate_content(prompt).text
            status.update(label="Análisis Finalizado", state="complete")

        # --- MOSTRAR RESULTADOS ---
        t1, t2, t3 = st.tabs(["📊 Estrategia de Venta", "🔧 Auditoría Técnica", "📄 Reporte PDF"])
        
        with t1:
            st.markdown(ai_report)
        
        with t2:
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Security Headers")
                if headers_info:
                    for k, v in headers_info.items():
                        st.write(f"{'✅' if v else '❌'} {k}")
            with col2:
                st.subheader("Detección de Servidor")
                st.code(headers_info.get("Server") if headers_info else "N/A")

        with t3:
            st.info("Genera un documento listo para enviar al Account Executive.")
            pdf_link = create_download_link(ai_report, f"Reporte_Akamai_{clean_target}")
            st.markdown(pdf_link, unsafe_allow_html=True)
            
            st.subheader("Raw Technical Logs")
            with st.expander("Ver logs completos"):
                st.text(contexto)

# --- IDEAS ADICIONALES PARA EL ANÁLISIS ---
st.sidebar.markdown("---")
st.sidebar.subheader("Próximas Mejoras Sugeridas:")
st.sidebar.write("""
- **Análisis DNS**: Chequear si usan DNS de Akamai o competidor (Route53/Cloudflare).
- **Time to First Byte (TTFB)**: Medir velocidad para vender **Ion**.
- **Detección de Cookies**: Buscar cookies de balanceadores conocidos.
- **SSL Labs Grade**: Integrar API de Qualys para ver la nota del certificado.
""")
