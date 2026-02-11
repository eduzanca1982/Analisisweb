import streamlit as st
import subprocess
from google import genai
import shutil
import requests
from fpdf import FPDF
import os

st.set_page_config(page_title="EdgeSight", layout="wide")

@st.cache_resource
def boot_gemini():
    try:
        if "GEMINI_API_KEY" not in st.secrets: return None, None
        client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])
        return client, "gemini-2.0-flash"
    except: return None, None

CLIENT, MODEL_ID = boot_gemini()

def run_command(cmd_list):
    if not shutil.which(cmd_list[0]): return ""
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=40)
        return result.stdout
    except: return ""

def get_dual_http_intel(domain):
    results = {}
    for proto in ["http://", "https://"]:
        try:
            res = requests.get(f"{proto}{domain}", timeout=5, verify=False)
            results[proto] = {
                "Server": res.headers.get("Server"),
                "CDN": res.headers.get("X-Cache", res.headers.get("CF-Cache-Status", "N/A")),
                "Status": res.status_code
            }
        except: results[proto] = "Error de conexión"
    return results

st.title("🛡️ EdgeSight")

if not CLIENT:
    st.error("Falta GEMINI_API_KEY")
    st.stop()

target = st.text_input("Dominio:", placeholder="empresa.com")

if st.button("🚀 Analizar"):
    if target:
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Analizando...", expanded=True):
            waf_info = run_command(["wafw00f", clean_target])
            whatweb_info = run_command(["whatweb", clean_target])
            dual_intel = get_dual_http_intel(clean_target)
            
            prompt = f"""
            Analiza estos datos técnicos de {clean_target}:
            WAF: {waf_info}
            WhatWeb: {whatweb_info}
            Headers Duales: {dual_intel}
            
            Genera un resumen de máximo 5 frases. 
            Menciona estrictamente: WAF, CDN y Web Server detectados.
            Reporta anomalías técnicas (ej. diferencias entre HTTP y HTTPS o versiones expuestas).
            Sin introducciones, sin saludos, directo al grano.
            """
            
            res = CLIENT.models.generate_content(model=MODEL_ID, contents=prompt)
            st.session_state.report = res.text
            st.session_state.target = clean_target

        if "report" in st.session_state:
            st.subheader("Estrategia")
            st.write(st.session_state.report)
            
            # Generación de PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=st.session_state.report.encode('latin-1', 'replace').decode('latin-1'))
            pdf_bytes = bytes(pdf.output())
            
            st.download_button("📥 PDF", data=pdf_bytes, file_name=f"{st.session_state.target}.pdf")
