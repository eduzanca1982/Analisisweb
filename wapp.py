import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

# Estilo corporativo Akamai
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #005595; color: white; font-weight: bold; }
    .stDownloadButton>button { background-color: #28a745; color: white; }
    </style>
    """, unsafe_allow_html=True)

# --- INICIALIZACIÓN DE CLIENTE GEMINI (vía Secrets) ---
try:
    # Intenta obtener la clave desde st.secrets
    api_key = st.secrets["GEMINI_API_KEY"]
    client = genai.Client(api_key=api_key)
except Exception:
    st.error("❌ No se encontró la GEMINI_API_KEY en los Secrets de Streamlit.")
    st.stop()

# --- FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no está disponible en el entorno."
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
        return {"Error": "No se pudo conectar al host"}

# --- INTERFAZ PRINCIPAL ---
st.title("🛡️ EdgeSight: Akamai Intelligence Tool")
st.markdown("### Herramienta de Prospección Técnica para Sales Engineers")

target = st.text_input("Dominio del Prospecto (ej: empresa.com):", placeholder="dominio.com")

if st.button("🚀 Iniciar Auditoría de Venta"):
    if target:
        # Limpieza de dominio
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Analizando infraestructura del prospecto...", expanded=True) as status:
            st.write("🛰️ Ejecutando WAFw00f (Detección de seguridad)...")
            waf_info = run_command(["wafw00f", clean_target])
            
            st.write("🔎 Ejecutando WhatWeb (Huella digital)...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🌐 Verificando Headers de Seguridad...")
            http_intel = get_http_intel(clean_target)
            
            st.write("🧠 Generando reporte estratégico con Gemini...")
            
            # Contexto para la IA
            context = f"""
            DOMINIO: {clean_target}
            WAFW00F LOG: {waf_info}
            WHATWEB LOG: {whatweb_info}
            HTTP HEADERS: {http_intel}
            """
            
            prompt = f"""
            Eres un Solution Engineer de Akamai especializado en Cloud Security y Delivery.
            Analiza los datos técnicos adjuntos para el sitio {clean_target}.
            
            Tu objetivo es armar un resumen para el equipo de ventas (Account Executives) que incluya:
            1. RECUENTO TECNOLÓGICO: ¿Qué CDN y WAF usan? ¿Están con la competencia (Cloudflare, AWS, Fastly)?
            2. BRECHAS DE SEGURIDAD: ¿Tienen headers de seguridad? ¿El servidor está expuesto?
            3. PITCH DE VENTA: ¿Por qué este cliente necesita Akamai App & API Protector o Bot Manager hoy mismo?
            4. PERFORMANCE: Si detectas que no usan CDN o el servidor es lento, menciona 'Akamai Ion'.
            
            Sé profesional, persuasivo y técnico.
            """
            
            try:
                response = client.models.generate_content(model="gemini-1.5-flash", contents=prompt)
                report_text = response.text
                status.update(label="Análisis Finalizado", state="complete")
            except Exception as e:
                st.error(f"Error con la API de Gemini: {e}")
                report_text = "Error al generar el reporte."

        # --- TABS DE RESULTADOS ---
        t_sales, t_tech, t_pdf = st.tabs(["📊 Estrategia de Venta", "🔧 Detalles Técnicos", "📥 Exportar"])
        
        with t_sales:
            st.markdown(report_text)
            
        with t_tech:
            st.write("**Headers de Seguridad Detectados:**")
            st.json(http_intel)
            with st.expander("Ver Logs Crudos de Herramientas"):
                st.subheader("WhatWeb")
                st.code(whatweb_info)
                st.subheader("WAFw00f")
                st.code(waf_info)

        with t_pdf:
            st.info("Genera un PDF para el briefing de la cuenta.")
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=12)
            pdf.cell(200, 10, txt=f"Akamai Sales Intelligence - {clean_target}", ln=1, align='C')
            pdf.ln(10)
            
            # Limpiar texto para evitar errores de encoding
            clean_pdf_text = report_text.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 10, txt=clean_pdf_text)
            
            pdf_bytes = pdf.output()
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_bytes,
                file_name=f"Akamai_Briefing_{clean_target}.pdf",
                mime="application/pdf"
            )
    else:
        st.error("Por favor, ingresa un dominio para analizar.")

st.sidebar.markdown("---")
st.sidebar.image("https://www.akamai.com/content/dam/site/en/images/logo/akamai-logo-rvb.png", width=150)
st.sidebar.caption("Herramienta de soporte preventa basada en reconocimiento pasivo.")
