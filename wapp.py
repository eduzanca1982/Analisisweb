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
    try:
        # Recuperación de clave configurada en Secrets
        api_key = st.secrets.get("GEMINI_API_KEY") 
        
        if not api_key:
            return "Error: No se encontró GEMINI_API_KEY en los secretos de Streamlit."

        # Actualización a gemini-2.0-flash para compatibilidad v1beta
        engine = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash", 
            google_api_key=api_key, 
            temperature=0
        )
        
        prompt = f"""
        Analizá este volcado técnico integral. 
        Identificá proveedores de WAF/CDN, red de origen (WHOIS), y configuraciones de borde.
        FORMATO: Solo bullets técnicos directos. Sin introducciones.
        
        VOLCADO:
        {raw_data}
        """
        response = engine.invoke([HumanMessage(content=prompt)])
        return response.content
    except Exception as e:
        return f"Error en el motor: {str(e)}"

def run_commands(target):
    audit = {}
    try:
        ip = socket.gethostbyname(target)
        audit["resolved_ip"] = ip
        
        # Wafw00f: Detección de WAF
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        audit["waf_raw"] = w_proc.stdout
        
        # WhatWeb: Huella tecnológica y Server Header
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        audit["tech_raw"] = ww_proc.stdout
        
        # WHOIS: Información de red e infraestructura
        whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True)
        audit["whois_raw"] = whois_proc.stdout
    except Exception as e:
        audit["error_ejecucion"] = str(e)
    return audit

target = st.text_input("Target Domain", placeholder="ejemplo.com.py")

if st.button("Ejecutar Análisis") and target:
    with st.spinner("Procesando infraestructura..."):
        data = run_commands(target)
        dump = json.dumps(data, indent=2)
        
        st.subheader("Resultados de Infraestructura")
        st.markdown(get_engine_analysis(dump))

        with st.expander("Ver volcado crudo de comandos"):
            st.code(dump, language="json")
