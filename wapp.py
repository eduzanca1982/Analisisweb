import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="EdgeSight | Akamai Sales Intel", layout="wide", page_icon="🛡️")

# --- API CLIENT ---
if 'api_key' not in st.session_state:
    st.session_state.api_key = ""

with st.sidebar:
    st.title("Configuración")
    st.session_state.api_key = st.text_input("Gemini API Key", type="password", value=st.session_state.api_key)

# --- FUNCIONES TÉCNICAS ---
def run_command(cmd_list):
    if not shutil.which(cmd_list[0]):
        return f"Error: {cmd_list[0]} no encontrado."
    try:
        # Añadido timeout y captura de errores
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=60)
        return f"{result.stdout}\n{result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"

def get_http_intelligence(url):
    try:
        if not url.startswith('http'): url = 'https://' + url
        res = requests.get(url, timeout=10, verify=False)
        h = res.headers
        return {
            "Server": h.get("Server", "Oculto"),
            "CDN": h.get("X-Cache", h.get("CF-Cache-Status", "N/A")),
            "HSTS": "Strict-Transport-Security" in h,
            "CSP": "Content-Security-Policy" in h
        }
    except:
        return {"Error": "No se pudo conectar"}

# --- INTERFAZ ---
st.title("🛡️ EdgeSight: Akamai Intelligence")

target = st.text_input("Dominio del Prospecto:", placeholder="ejemplo.com")

if st.button("🚀 Iniciar Auditoría"):
    if not st.session_state.api_key:
        st.error("Falta API Key.")
    elif target:
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("🔍 Analizando...", expanded=True) as status:
            # Cambio de w00fwaf a wafw00f (comando oficial)
            st.write("🛰️ Identificando WAF (wafw00f)...")
            waf_info = run_command(["wafw00f", clean_target])
            
            st.write("🔎 Huella digital (WhatWeb)...")
            whatweb_info = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("🧠 Generando reporte IA...")
            client = genai.Client(api_key=st.session_state.api_key)
            
            prompt = f"Actúa como SE de Akamai. Analiza estos datos de {clean_target} y crea un pitch de venta: \nLogs:\n{whatweb_info}\n{waf_info}"
            response = client.models.generate_content(model="gemini-1.5-flash", contents=prompt)
            report_text = response.text
            status.update(label="Análisis Completo", state="complete")

        # --- TABS ---
        t1, t2, t3 = st.tabs(["📊 Estrategia", "🔧 Técnica", "📥 PDF"])
        
        with t1:
            st.markdown(report_text)
            
        with t2:
            st.code(f"--- WAF DETECTION ---\n{waf_info}\n\n--- WHATWEB ---\n{whatweb_info}")

        with t3:
            # Generación de PDF con fpdf2
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=12)
            pdf.cell(200, 10, txt="Akamai Sales Intelligence Report", ln=1, align='C')
            pdf.ln(10)
            # Limpiar caracteres no latin-1
            safe_text = report_text.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 10, txt=safe_text)
            
            pdf_bytes = pdf.output()
            st.download_button(
                label="Descargar PDF",
                data=pdf_bytes,
                file_name=f"Akamai_{clean_target}.pdf",
                mime="application/pdf"
            )
