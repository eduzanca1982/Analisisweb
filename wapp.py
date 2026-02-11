import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

# CSS para mejorar la estética corporativa
st.markdown("""
    <style>
    .main { background-color: #f8f9fa; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #005595; color: white; }
    .stDownloadButton>button { background-color: #28a745; color: white; }
    </style>
    """, unsafe_allow_html=True)

# --- API CLIENT (NUEVO SDK) ---
if 'api_key' not in st.session_state:
    st.session_state.api_key = ""

with st.sidebar:
    st.title("Configuración")
    st.session_state.api_key = st.text_input("Gemini API Key", type="password", value=st.session_state.api_key)
    st.info("Esta app usa escaneos pasivos para ayudar en la preventa de soluciones Akamai.")

# --- FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    """Ejecuta comandos de sistema de forma segura."""
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no está instalado en el servidor."
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=40)
        return f"{result.stdout}\n{result.stderr}"
    except Exception as e:
        return f"Error de ejecución: {str(e)}"

def get_http_intelligence(url):
    """Analiza headers de seguridad y servidor."""
    try:
        if not url.startswith('http'): url = 'https://' + url
        res = requests.get(url, timeout=10, verify=False) # verify=False para evitar problemas con certs autofirmados en el escaneo
        h = res.headers
        return {
            "Server": h.get("Server", "Oculto"),
            "CDN-Check": h.get("X-Cache", h.get("CF-Cache-Status", "N/A")),
            "HSTS": "Strict-Transport-Security" in h,
            "CSP": "Content-Security-Policy" in h,
            "Permissions-Policy": "Permissions-Policy" in h
        }
    except Exception as e:
        return {"Error": str(e)}

# --- INTERFAZ PRINCIPAL ---
st.title("🛡️ EdgeSight: Akamai Intelligence Tool")
st.subheader("Análisis de infraestructura para Sales Engineering")

target = st.text_input("Dominio del Prospecto (ej: prospecto.com)", placeholder="dominio.com")

if st.button("🚀 Iniciar Auditoría de Venta"):
    if not st.session_state.api_key:
        st.error("Por favor, ingresa la API Key de Gemini en la barra lateral.")
    elif target:
        # Sanitizar target
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Realizando reconocimiento pasivo...", expanded=True) as status:
            st.write("🛰️ Identificando WAF...")
            waf_info = run_command(["w00fwaf", clean_target])
            
            st.write("🔎 Analizando huella digital (WhatWeb)...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🌐 Verificando Headers de Seguridad...")
            http_intel = get_http_intelligence(clean_target)
            
            st.write("🧠 Consultando con Gemini AI...")
            try:
                client = genai.Client(api_key=st.session_state.api_key)
                full_context = f"""
                CLIENTE: {clean_target}
                WHATWEB: {whatweb_info}
                WAF: {waf_info}
                HEADERS: {http_intel}
                """
                
                prompt = f"""
                Eres un Solution Engineer de Akamai. Analiza estos datos técnicos para una oportunidad de venta.
                Estructura tu respuesta:
                1. STACK ACTUAL: Proveedores detectados.
                2. PAIN POINTS: Vulnerabilidades (falta de headers) o uso de competidores.
                3. PROPUESTA AKAMAI: Por qué necesitan 'App & API Protector' o 'Ion'.
                """
                
                response = client.models.generate_content(model="gemini-1.5-flash", contents=prompt)
                report_text = response.text
                status.update(label="Análisis Completo", state="complete")
            except Exception as e:
                st.error(f"Error con Gemini: {e}")
                report_text = "No se pudo generar el reporte IA."

        # --- TABS DE RESULTADOS ---
        tab_sales, tab_tech, tab_pdf = st.tabs(["📊 Estrategia Comercial", "🔧 Detalles Técnicos", "📥 Exportar"])
        
        with tab_sales:
            st.markdown(report_text)
            
        with tab_tech:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Seguridad de Headers:**")
                st.json(http_intel)
            with col2:
                st.write("**Detección de Infraestructura:**")
                st.text(f"WAF: {waf_info[:200]}...") # Resumen corto
            
            with st.expander("Ver Logs Crudos Completos"):
                st.code(f"--- WHATWEB ---\n{whatweb_info}\n\n--- W0
