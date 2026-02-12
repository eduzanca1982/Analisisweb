import streamlit as st
import subprocess
import socket
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="Edge Snapshot", layout="wide")
st.title("Scan Apukay EZ - IA Driven Analysis")

def get_ai_interpretation(raw_data):
    """La IA procesa el volcado total de los comandos sin reglas rígidas."""
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash", 
            google_api_key=st.secrets["GOOGLE_API_KEY"], 
            temperature=0
        )
        
        prompt = f"""
        Sos un experto en infraestructura y ciberseguridad. 
        Analizá el siguiente volcado de comandos técnicos (WhatWeb, Wafw00f, WHOIS, Headers).
        
        TAREAS:
        1. Identificá el WAF y CDN basándote en CUALQUIER indicio (headers, rangos de IP, firmas de servidor).
        2. Analizá la IP que responde y a quién pertenece realmente.
        3. Detectá discrepancias (ej. el certificado dice una cosa, el WHOIS otra).
        4. Exponé parámetros críticos de seguridad encontrados.

        FORMATO: Solo bullets técnicos directos. Sin introducciones.
        
        VOLCADO TÉCNICO:
        {raw_data}
        """
        return llm.invoke([HumanMessage(content=prompt)]).content
    except Exception as e:
        return f"Error en procesamiento de IA: {str(e)}"

def run_aggressive_commands(target):
    # Diccionario para acumular todo lo que la IA va a leer
    audit_trail = {}

    # 1. Resolución de IP
    try:
        ip = socket.gethostbyname(target)
        audit_trail["resolved_ip"] = ip
    except:
        ip = "N/A"

    # 2. Wafw00f (Modo diagnóstico)
    try:
        w_proc = subprocess.run(['wafw00f', target, '-v'], capture_output=True, text=True)
        audit_trail["wafw00f_full_output"] = w_proc.stdout
    except Exception as e:
        audit_trail["wafw00f_error"] = str(e)

    # 3. WhatWeb (Modo agresivo nivel 3)
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
            audit_trail["whois_error"] = "No se pudo ejecutar whois"

    return audit_trail

target = st.text_input("Target Domain", placeholder="bancognb.com.py")

if st.button("Ejecutar Auditoría IA") and target:
    with st.spinner("Ejecutando comandos y procesando con IA..."):
        # Ejecución de comandos
        raw_audit_data = run_aggressive_commands(target)
        
        # Convertimos todo el diccionario a un string gigante para la IA
        full_dump = json.dumps(raw_audit_data, indent=2)
        
        # Resultados
        st.subheader("IA Technical Insights (Interpretación Dinámica)")
        analysis = get_ai_interpretation(full_dump)
        st.markdown(analysis)

        st.divider()

        # Debug/Raw data para el usuario
        with st.expander("Ver volcado crudo enviado a la IA"):
            st.code(full_dump, language="json")
