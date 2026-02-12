import streamlit as st
import subprocess
import socket
import json
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide")
st.title("Scan Apukay EZ - Análisis de Infraestructura")

def get_engine_analysis(raw_data):
    """Procesamiento dinámico de los outputs de comandos."""
    try:
        # Intento de recuperación del secreto desde st.secrets o variables de entorno
        api_key = st.secrets.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        
        if not api_key:
            return "Error: No se encontró la configuración de acceso (GOOGLE_API_KEY)."

        engine = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash", 
            google_api_key=api_key, 
            temperature=0
        )
        
        prompt = f"""
        Analizá el siguiente volcado de comandos técnicos (WhatWeb, Wafw00f, WHOIS, Headers).
        
        TAREAS:
        1. Identificá el WAF y CDN basándote en headers, rangos de IP y firmas de servidor.
        2. Analizá la IP de respuesta y su pertenencia de red.
        3. Detectá discrepancias entre certificado, WHOIS y respuesta de headers.
        4. Exponé parámetros críticos de seguridad encontrados.

        FORMATO: Solo bullets técnicos directos. Sin introducciones ni cierres.
        
        VOLCADO TÉCNICO:
        {raw_data}
        """
        response = engine.invoke([HumanMessage(content=prompt)])
        return response.content
    except Exception as e:
        return f"Error en el motor de análisis: {str(e)}"

def run_aggressive_commands(target):
    audit_trail = {}

    # 1. Resolución de IP
    try:
        ip = socket.gethostbyname(target)
        audit_trail["resolved_ip"] = ip
    except:
        ip = "N/A"

    # 2. Wafw00f (Diagnóstico)
    try:
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        audit_trail["wafw00f_full_output"] = w_proc.stdout
    except Exception as e:
        audit_trail["wafw00f_error"] = str(e)

    # 3. WhatWeb (Agresivo nivel 3)
    try:
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        audit_trail["whatweb_full_output"] = ww_proc.stdout
    except Exception as e:
        audit_trail["whatweb_error"] = str(e)

    # 4. WHOIS de la IP
    if ip != "N/A":
        try:
            whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True)
            audit_trail["whois_ip_data"] = whois_proc.stdout
        except:
            audit_trail["whois_error"] = "Falla en ejecución de whois"

    return audit_trail

target = st.text_input("Target Domain", placeholder="ejemplo.com.py")

if st.button("Ejecutar Auditoría") and target:
    with st.spinner("Procesando infraestructura..."):
        # Ejecución de comandos de sistema
        raw_audit_data = run_aggressive_commands(target)
        
        # Consolidación de datos para el motor
        full_dump = json.dumps(raw_audit_data, indent=2)
        
        # Resultados de la interpretación
        st.subheader("Insights de Infraestructura")
        analysis = get_engine_analysis(full_dump)
        st.markdown(analysis)

        st.divider()

        # Debug/Raw data
        with st.expander("Ver volcado crudo de comandos"):
            st.code(full_dump, language="json")
