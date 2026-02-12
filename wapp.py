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
        # Sincronización con el nombre exacto que configuraste en Streamlit Cloud
        api_key = st.secrets.get("GEMINI_API_KEY") 
        
        if not api_key:
            return "Error: No se encontró GEMINI_API_KEY en los secretos de Streamlit."

        engine = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash", 
            google_api_key=api_key, 
            temperature=0
        )
        
        prompt = f"""
        Analizá el siguiente volcado técnico. 
        Identificá WAF/CDN, pertenencia de red (WHOIS), y discrepancias de seguridad.
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
        audit["ip"] = ip
        
        # Wafw00f
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        audit["waf_raw"] = w_proc.stdout
        
        # WhatWeb
        ww_proc = subprocess.run(['whatweb', '-a', '3', target, '--color=never'], capture_output=True, text=True)
        audit["tech_raw"] = ww_proc.stdout
        
        # WHOIS
        whois_proc = subprocess.run(['whois', ip], capture_output=True, text=True)
        audit["whois_raw"] = whois_proc.stdout
    except Exception as e:
        audit["error"] = str(e)
    return audit

target = st.text_input("Target Domain", placeholder="ejemplo.com.py")

if st.button("Ejecutar Análisis") and target:
    with st.spinner("Procesando..."):
        data = run_commands(target)
        dump = json.dumps(data, indent=2)
        
        st.subheader("Resultados de Infraestructura")
        st.markdown(get_engine_analysis(dump))

        with st.expander("Ver volcado crudo"):
            st.code(dump, language="json")
