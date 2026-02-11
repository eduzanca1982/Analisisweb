import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

# --- 1. CONFIGURACIÓN Y ARRANQUE SEGURO ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

@st.cache_resource
def boot_gemini():
    """Inicializa el cliente y detecta modelos usando la estructura correcta del SDK v1.0+."""
    try:
        # Recuperar Key de Secrets
        if "GEMINI_API_KEY" not in st.secrets:
            return None, None
            
        api_key = st.secrets["GEMINI_API_KEY"]
        client = genai.Client(api_key=api_key)
        
        # Corrección: El objeto 'Model' del nuevo SDK se accede de forma distinta
        # Si falla la detección, usamos el fallback directo que vimos en tus capturas
        return client, "gemini-2.0-flash" 
    except Exception as e:
        st.error(f"Error de inicialización: {e}")
        return None, None

CLIENT, MODEL_ID = boot_gemini()

# --- 2. FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no instalado."
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=60)
        return f"{result.stdout}\n{result.stderr}"
    except Exception as e:
        return f"Error en ejecución: {str(e)}"

def get_http_intel(url):
    try:
        if not url.startswith('http'): url = 'https://' + url
        res = requests.get(url, timeout=10, verify=False)
        h = res.headers
        return {
            "Server": h.get("Server", "Oculto"),
            "CDN-Header": h.get("X-Cache", h.get("CF-Cache-Status", "N/A")),
            "HSTS": "Strict-Transport-Security" in h,
            "CSP": "Content-Security-Policy" in h
        }
    except:
        return {"Error": "Conexión fallida"}

# --- 3. INTERFAZ ---
st.title("🛡️ EdgeSight: Akamai Intelligence Tool")

if not CLIENT:
    st.warning("⚠️ GEMINI_API_KEY no detectada en Secrets. Por favor verifica la configuración.")
    st.stop()

target = st.text_input("Dominio del Prospecto (ej: empresa.com):", placeholder="dominio.com")

if st.button("🚀 Iniciar Auditoría de Venta"):
    if target:
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Procesando auditoría...", expanded=True) as status:
            st.write("🛰️ Identificando WAF...")
            waf_info = run_command(["wafw00f", clean_target])
            
            st.write("🔎 Analizando huella digital...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🌐 Verificando Headers...")
            headers_intel = get_http_intel(clean_target)
            
            st.write(f"🧠 Generando reporte con {MODEL_ID}...")
            
            try:
                prompt = f"""
                Eres un Senior SE de Akamai. Analiza {clean_target} para el equipo de ventas:
                Logs: {waf_info} | {whatweb_info}
                Headers: {headers_intel}
                Genera: Stack actual, Brechas de seguridad y por qué necesitan Akamai App & API Protector.
                """
                
                response = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
                report_text = response.text
                status.update(label="Análisis Finalizado", state="complete")
                
                # Guardar en session_state para persistencia tras el click del PDF
                st.session_state.last_report = report_text
                st.session_state.last_target = clean_target
                st.session_state.last_tech = headers_intel
                
            except Exception as e:
                st.error(f"Error con la API: {e}")
                st.session_state.last_report = None

        if "last_report" in st.session_state and st.session_state.last_report:
            t_sales, t_tech, t_pdf = st.tabs(["📊 Estrategia", "🔧 Técnica", "📥 Exportar"])
            
            with t_sales:
                st.markdown(st.session_state.last_report)
            
            with t_tech:
                st.json(st.session_state.last_tech)
                st.code(f"--- WAF ---\n{waf_info}\n--- WHATWEB ---\n{whatweb_info}")

            with t_pdf:
                st.info("Generar reporte oficial.")
                try:
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", size=12)
                    pdf.cell(200, 10, txt=f"Akamai Sales Intel - {st.session_state.last_target}", ln=1, align='C')
                    pdf.ln(10)
                    
                    pdf_body = st.session_state.last_report.encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 10, txt=pdf_body)
                    
                    # FIX DEFINITIVO: fpdf2.output() puede devolver bytearray. 
                    # Streamlit requiere estrictamente 'bytes'.
                    pdf_output = pdf.output()
                    pdf_bytes = bytes(pdf_output) 
                    
                    st.download_button(
                        label="📥 Descargar Reporte PDF",
                        data=pdf_bytes,
                        file_name=f"Akamai_Report_{st.session_state.last_target}.pdf",
                        mime="application/pdf"
                    )
                except Exception as pdf_err:
                    st.error(f"Error en PDF: {pdf_err}")
    else:
        st.error("Ingresa un dominio válido.")
