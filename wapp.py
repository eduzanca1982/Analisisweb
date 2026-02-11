import streamlit as st
import subprocess
import google-generativeai as genai
import shlex

# Configuración de API
GEMINI_API_KEY = "TU_API_KEY_AQUI"
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

def run_command(cmd_list):
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=40)
        return f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"

def analyze_for_sales(target, raw_data):
    prompt = f"""
    Eres un Solution Engineer experto en Akamai Technologies. 
    Analiza la infraestructura de {target} basándote en estos logs técnicos:
    
    {raw_data}
    
    Tu objetivo es generar un informe comercial estratégico que incluya:
    1. STACK ACTUAL: Identificar CDN, WAF, Web Server y Proveedor de Hosting.
    2. CERTIFICADOS Y SEGURIDAD: Detalles del SSL y headers de seguridad detectados.
    3. PUNTOS DE DOLOR (Pain Points): Identificar si usan la competencia (Cloudflare, AWS, Fastly) o si no tienen protección aparente.
    4. VALOR AGREGADO AKAMAI: Sugerir qué productos de Akamai (App & API Protector, Bot Manager, Ion, etc.) resolverían problemas específicos detectados.
    
    Usa un tono profesional, ejecutivo y persuasivo para ventas.
    """
    response = model.generate_content(prompt)
    return response.text

# Interfaz Streamlit
st.set_page_config(page_title="Akamai Sales Intelligence Tool", layout="wide")
st.title("🚀 Akamai Prospect Intelligence")

target = st.text_input("Dominio del Cliente Potencial:", placeholder="ejemplo.com")

if st.button("Generar Brief de Venta"):
    if target:
        # Limpieza de input
        clean_target = target.replace("https://", "").replace("http://", "").split('/')[0]
        
        with st.status("Analizando infraestructura del prospecto...") as status:
            # Ejecución de herramientas
            st.write("Detectando tecnologías...")
            whatweb_out = run_command(["whatweb", "--aggression", "1", clean_target])
            
            st.write("Verificando capas de seguridad...")
            waf_out = run_command(["w00fwaf", clean_target])
            
            # Análisis de IA
            st.write("Generando estrategia de venta...")
            full_log = f"{whatweb_out}\n{waf_out}"
            sales_report = analyze_for_sales(clean_target, full_log)
            
            status.update(label="Análisis de Cuenta Completo", state="complete")

        # Visualización
        tab1, tab2 = st.tabs(["Estrategia de Venta", "Datos Técnicos"])
        
        with tab1:
            st.markdown(sales_report)
            
        with tab2:
            st.subheader("Logs de WhatWeb")
            st.code(whatweb_out)
            st.subheader("Logs de w00fwaf")
            st.code(waf_out)
    else:
        st.error("Ingresa un dominio para continuar.")
