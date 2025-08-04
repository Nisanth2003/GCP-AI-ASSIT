import streamlit as st

from streamlit_lottie import st_lottie

import requests

import json

from typing import Optional

from datetime import datetime

from pandas import DataFrame
 
# Constants

LOTTIE_URL = "https://assets2.lottiefiles.com/packages/lf20_v1yudlrx.json"

API_ENDPOINT = "http://localhost:8000/process_query"

TIMEOUT = 15  # seconds
 
class AppConfig:

    """Handles app configuration and styling"""
 
    @staticmethod

    def setup_page():

        st.set_page_config(

            page_title="GCP AI Query Assistant",

            page_icon="☁️",

            layout="centered",

            initial_sidebar_state="collapsed"

        )
 
    @staticmethod

    def apply_styles():

        st.markdown("""
<style>

            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');

            html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

            .main { background: linear-gradient(135deg, #f5f7fa 0%, #e4edf5 100%); }

            .stButton > button {

                background: linear-gradient(90deg, #1a73e8, #4285f4);

                color: white;

                font-weight: 600;

                border-radius: 30px;

                border: none;

                padding: 0.55em 1.5em;

                font-size: 1rem;

                box-shadow: 0 4px 14px 0 rgba(31, 38, 135, 0.2);

                transition: all 0.3s ease;

            }

            .stButton > button:hover {

                transform: translateY(-2px);

                box-shadow: 0 6px 20px 0 rgba(31, 38, 135, 0.4);

            }

            .stTextInput > div > div > input {

                border-radius: 20px;

                border: 1px solid #ccc;

                padding: 0.75em 1em;

                font-size: 1rem;

            }

            .footer {

                text-align: center;

                margin-top: 4rem;

                font-size: 0.8rem;

                color: #666;

            }

            .result-card {

                border-radius: 10px;

                padding: 1.5em;

                margin: 1em 0;

                background: white;

                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);

            }
</style>

        """, unsafe_allow_html=True)
 
class AnimationLoader:

    """Handles Lottie animation loading"""
 
    @staticmethod

    def load_lottie(url: str) -> Optional[dict]:

        try:

            r = requests.get(url, timeout=2)

            return r.json() if r.status_code == 200 else None

        except Exception:

            return None
 
class BackendCommunicator:

    """Handles communication with the backend API"""
 
    @staticmethod

    def process_query(query: str) -> Optional[dict]:

        try:

            response = requests.post(

                API_ENDPOINT,

                json={"query": query},

                timeout=TIMEOUT

            )

            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as e:

            st.error(f"Failed to connect to backend: {str(e)}")

            return None
 
def display_header():

    """Displays the app header and animation"""

    st.markdown(

        "<h1 style='text-align:center;font-weight:600;font-size:2.8rem;color:#1a73e8;'>☁️ GCP AI Query Assistant</h1>",

        unsafe_allow_html=True

    )

    st.markdown(

        "<p style='text-align:center;font-size:1.2rem;color:#555;margin-top:-10px;'>Ask anything about your Google Cloud resources in plain English.</p>",

        unsafe_allow_html=True

    )
 
    lottie_json = AnimationLoader.load_lottie(LOTTIE_URL)

    if lottie_json:

        st_lottie(lottie_json, height=180, key="hero")
 
def display_footer():

    """Displays the app footer"""

    current_year = datetime.now().year

    st.markdown(

        f"<div class='footer'>Built with ❤️ and Streamlit | © {current_year}</div>",

        unsafe_allow_html=True

    )
 
def display_result_tables(data):

    """Dynamic and pretty display of parsed backend results"""

    parsed_data = data.get("data", {})
 
    # Split fields into metrics (scalar) and lists

    metrics = {}

    list_fields = {}
 
    for key, value in parsed_data.items():

        label = key.replace("_", " ").title()
 
        if isinstance(value, (str, int, float, bool)):

            metrics[label] = value

        elif isinstance(value, list) and all(isinstance(x, str) for x in value):

            list_fields[label] = value

        elif isinstance(value, list) and all(isinstance(x, dict) for x in value):

            # Optional: handle list of dicts as full tables

            st.subheader(f"📋 {label}")

            st.dataframe(DataFrame(value))
 
    # Summary table

    if metrics:

        st.subheader("📊 Summary")

        st.table(DataFrame(metrics.items(), columns=["Metric", "Value"]))
 
    # Each string list as a table

    for label, items in list_fields.items():

        st.subheader(f"📋 {label}")

        st.table(DataFrame(items, columns=["Value"]))
 
def main():

    AppConfig.setup_page()

    AppConfig.apply_styles()

    display_header()
 
    with st.container():

        query = st.text_input(

            "Enter your query:",

            placeholder="e.g. list all compute instances in us-central1-a",

            key="query_input"

        )

        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:

            ask_button = st.button("Ask Gemini", use_container_width=True, key="ask_button")
 
    if ask_button and query.strip():

        with st.spinner("🔄 Consulting Gemini..."):

            result = BackendCommunicator.process_query(query.strip())

            # st.write("📦 DEBUG: Raw backend result:", result)//json format result.
 
            if result and "data" in result:

                data_str = result["data"]
 
                try:

                    json_start = data_str.find("{")

                    json_str = data_str[json_start:]

                    data = json.loads(json_str)
 
                    st.success("✅ Gemini command:")

                    st.code(result.get("command", ""), language="bash")
 
                    display_result_tables(data)
 
                    if not result.get("success") and result.get("error"):

                        st.error(f"❌ {result['error']}")

                except Exception as e:

                    st.error("⚠️ Failed to parse backend 'data' field.")

                    st.text(data_str)

            else:

                st.error("❌ Invalid response from backend. Please try again.")
 
    display_footer()
 
if __name__ == "__main__":

    main()

 