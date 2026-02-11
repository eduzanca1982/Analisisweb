import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os
import time

# --- 1. CONFIGURACIÓN Y ARRANQUE SEGURO ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

@st.cache_resource
def boot_gemini():
    """Inicializa el cliente y detecta modelos para evitar errores de conexión repetitivos."""
    try:
        api_key = st.secrets["GEMINI_API_KEY"]
        client = genai.Client(api_key=api_key)
        # Intentamos detectar si el modelo flash está disponible
        modelos = [m.name for m in client.models.list() if 'generateContent' in m.supported_methods]
        # Priorizamos gemini-2.0-flash como vimos en tus capturas
        target_model = next((m for m in modelos if "gemini-2.0-flash" in m), "gemini-1.5-flash")
        return client, target_model
    except Exception as e:
        st.error(f"Error crítico de inicialización: {e}")
        return None, None

CLIENT, MODEL_ID = boot_gemini()

# --- 2. FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no instalado."
    try:
        # Timeout para evitar que procesos colgados consuman recursos
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
    st.warning("⚠️ Configura la GEMINI_API_KEY en Secrets para continuar.")
    st.stop()

target = st.text_input("Dominio del Prospecto (ej: empresa.com):", placeholder="dominio.com")

if st.button("🚀 Iniciar Auditoría de Venta"):
    if target:
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Procesando auditoría...", expanded=True) as status:
            # Reconocimiento pasivo
            st.write("🛰️ Ejecutando wafw00f...")
            waf_info = run_command(["wafw00f", clean_target])
            
            st.write("🔎 Ejecutando WhatWeb...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🌐 Verificando Headers...")
            headers_intel = get_http_intel(clean_target)
            
            st.write(f"🧠 Consultando IA ({MODEL_ID})...")
            
            # Defensa contra 429 y generación de contenido
            try:
                prompt = f"""
                Actúa como Senior SE de Akamai. Analiza {clean_target}:
                Logs: {waf_info} | {whatweb_info}
                Headers: {headers_intel}
                Genera un Briefing de Ventas con: Stack actual, Brechas de seguridad y Pitch para Akamai App & API Protector.
                """
                
                # Intentar llamada a la API
                response = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
                report_text = response.text
                status.update(label="Análisis Finalizado", state="complete")
                
            except Exception as e:
                if "429" in str(e):
                    st.error("🚫 Cuota excedida (Error 429). Por favor, espera un minuto antes de intentar de nuevo.")
                else:
                    st.error(f"Error con la API: {e}")
                report_text = f"Error al generar reporte: {e}"

        # --- TABS DE RESULTADOS ---
        t_sales, t_tech, t_pdf = st.tabs(["📊 Estrategia de Venta", "🔧 Datos Técnicos", "📥 Exportar"])
        
        with t_sales:
            st.markdown(report_text)
            
        with t_tech:
            st.write("**Seguridad detectada:**")
            st.json(headers_intel)
            with st.expander("Ver Logs Crudos"):
                st.code(f"--- WHATWEB ---\n{whatweb_info}\n\n--- WAFW00F ---\n{waf_info}")

        with t_pdf:
            st.info("Generar reporte oficial.")
            try:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                pdf.cell(200, 10, txt=f"Akamai Sales Intelligence - {clean_target}", ln=1, align='C')
                pdf.ln(10)
                
                # Sanitización para evitar errores de codificación
                pdf_body = report_text.encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 10, txt=pdf_body)
                
                # FIX CRÍTICO: Convertir output a bytes explícitamente
                pdf_bytes = bytes(pdf.output())
                
                st.download_button(
                    label="📥 Descargar Reporte PDF",
                    data=pdf_bytes,
                    file_name=f"Akamai_Report_{clean_target}.pdf",
                    mime="application/pdf"
                )
            except Exception as pdf_err:
                st.error(f"Error generando PDF: {pdf_err}")

    else:
        st.error("Ingresa un dominio válido.")

st.sidebar.caption(f"Modelo activo: {MODEL_ID}")
