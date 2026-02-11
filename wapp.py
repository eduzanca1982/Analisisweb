import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

# Estilo corporativo para el equipo de ventas
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #005595; color: white; font-weight: bold; }
    .stDownloadButton>button { background-color: #28a745; color: white; }
    </style>
    """, unsafe_allow_html=True)

# --- CONFIGURACIÓN DEL MODELO (Basado en tus capturas) ---
try:
    # Obtiene la clave de Secrets de Streamlit
    api_key = st.secrets["GEMINI_API_KEY"]
    client = genai.Client(api_key=api_key)
    # Usamos el ID exacto confirmado en tu Google AI Studio
    MODEL_ID = "gemini-2.0-flash" 
except Exception as e:
    st.error(f"Error de configuración (Secrets/API): {e}")
    st.stop()

# --- FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    """Ejecuta herramientas de CLI instaladas en el servidor."""
    if not shutil.which(cmd_list[0]):
        return f"Error: La herramienta {cmd_list[0]} no está instalada."
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=60)
        return f"{result.stdout}\n{result.stderr}"
    except Exception as e:
        return f"Error en ejecución: {str(e)}"

def get_http_intel(url):
    """Analiza headers de seguridad básicos."""
    try:
        if not url.startswith('http'): url = 'https://' + url
        # Desactivamos verify para evitar bloqueos por certificados mal configurados en prospectos
        res = requests.get(url, timeout=10, verify=False)
        h = res.headers
        return {
            "Server": h.get("Server", "No expuesto"),
            "Cache-Control": h.get("Cache-Control", "N/A"),
            "HSTS": "Strict-Transport-Security" in h,
            "CSP": "Content-Security-Policy" in h
        }
    except:
        return {"Error": "No se pudo conectar al host"}

# --- INTERFAZ PRINCIPAL ---
st.title("🛡️ EdgeSight: Akamai Intelligence Tool")
st.markdown("### Soporte de Preventa para Account Executives y SEs")

target = st.text_input("Ingresa el dominio del prospecto:", placeholder="ejemplo.com")

if st.button("🚀 Iniciar Auditoría Técnica"):
    if target:
        # Limpieza de entrada
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Escaneando infraestructura...", expanded=True) as status:
            st.write("🛰️ Ejecutando wafw00f...")
            waf_info = run_command(["wafw00f", clean_target])
            
            st.write("🔎 Ejecutando WhatWeb...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🌐 Analizando HTTP Headers...")
            headers_intel = get_http_intel(clean_target)
            
            st.write(f"🧠 Generando estrategia con {MODEL_ID}...")
            
            # Prompt estratégico para ventas de Akamai
            prompt = f"""
            Actúa como un Senior Solution Engineer de Akamai Technologies.
            Analiza los datos técnicos del sitio: {clean_target}
            
            LOGS TÉCNICOS:
            - WAF Detection: {waf_info}
            - WhatWeb Footprint: {whatweb_info}
            - Security Headers: {headers_intel}
            
            Tu objetivo es crear un Briefing de Ventas que incluya:
            1. Infraestructura Actual: ¿Qué CDN/WAF usan hoy?
            2. Brechas y Oportunidades: Si no tienen WAF o usan competencia (Cloudflare, AWS), ¿por qué Akamai es mejor?
            3. Propuesta de Valor: Menciona productos específicos (App & API Protector, Ion, Bot Manager).
            4. Pitch Sugerido: Una frase de apertura para el Account Executive.
            """
            
            try:
                response = client.models.generate_content(model=MODEL_ID, contents=prompt)
                report_text = response.text
                status.update(label="Análisis Finalizado", state="complete")
            except Exception as e:
                st.error(f"Error con la API de Gemini: {e}")
                report_text = "No se pudo generar el reporte."

        # --- TABS DE RESULTADOS ---
        t_sales, t_tech, t_pdf = st.tabs(["📊 Estrategia de Venta", "🔧 Datos Crudos", "📥 Reporte PDF"])
        
        with t_sales:
            st.markdown(report_text)
            
        with t_tech:
            st.write("**Headers de Seguridad:**")
            st.json(headers_intel)
            with st.expander("Ver Logs de Herramientas"):
                st.subheader("WhatWeb")
                st.code(whatweb_info)
                st.subheader("WAFw00f")
                st.code(waf_info)

        with t_pdf:
            st.info("Genera un documento PDF para enviar al cliente o al equipo interno.")
            
            # Generación de PDF con fpdf2
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=12)
            pdf.cell(200, 10, txt=f"Akamai Sales Intel: {clean_target}", ln=1, align='C')
            pdf.ln(10)
            
            # Limpiar texto para evitar errores de codificación
            clean_pdf_text = report_text.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 10, txt=clean_pdf_text)
            
            # Convertir a bytes para el botón de Streamlit
            pdf_output = pdf.output()
            
            st.download_button(
                label="📥 Descargar PDF para AE",
                data=pdf_output,
                file_name=f"Akamai_Report_{clean_target}.pdf",
                mime="application/pdf"
            )
    else:
        st.error("Por favor, ingresa un dominio válido.")

st.sidebar.markdown("---")
st.sidebar.caption("Herramienta interna basada en escaneos pasivos.")
