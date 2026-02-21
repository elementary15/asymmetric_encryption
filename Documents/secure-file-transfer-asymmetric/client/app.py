import streamlit as st
import tempfile
import os
import sys

# --- ROBUST PATH LOADING ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))

if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Attempt to import the function directly from the file to avoid naming collisions
try:
    import client.client as client_file
    upload_file = client_file.upload_file
except (ImportError, ModuleNotFoundError):
    # Fallback if Python treats 'client' as a module instead of a package
    import client as client_mod
    upload_file = client_mod.upload_file

st.set_page_config(page_title="Secure File Transfer", layout="centered")

st.title("🛡️ Secure File Transfer System")

uploaded_file = st.file_uploader("Choose a file to upload")

if uploaded_file:
    temp_dir = tempfile.gettempdir()
    tmp_path = os.path.join(temp_dir, uploaded_file.name)
    
    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    if st.button("🚀 Upload to Server"):
        with st.spinner("Encrypting and transferring..."):
            result = upload_file(tmp_path)

        if result == "OK":
            st.success(f"Success! '{uploaded_file.name}' verified.")
        elif result == "SIGNATURE_INVALID":
            st.error("Authentication Failed: Signature is invalid.")
        elif result == "CONNECTION_FAILED":
            st.error("Could not connect to server.")
        else:
            st.error(f"Upload failed: {result}")

        if os.path.exists(tmp_path):
            os.remove(tmp_path)