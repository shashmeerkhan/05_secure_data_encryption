import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Generate a Fernet key from the passkey
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data:
            stored_info = st.session_state.stored_data[data_id]
            if stored_info['passkey'] == hashed_passkey:
                key = generate_key_from_passkey(passkey)
                cipher = Fernet(key)
                decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
                return decrypted_text
            else:
                raise Exception("Invalid passkey")
        else:
            raise Exception("Invalid Data ID")
    except Exception as e:
        raise e

# Save encrypted data
def save_data(data_id, encrypted_text, hashed_passkey):
    st.session_state.stored_data[data_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    }

# Home page
def home():
    st.title("🔐 Secure Data Encryption App")
    st.write("Welcome! Choose an option from the sidebar.")

# Encrypt page
def encrypt_page():
    st.title("🔒 Encrypt Your Data")

    text = st.text_area("Enter the text to encrypt")
    passkey = st.text_input("Enter a passkey", type="password")
    data_id = st.text_input("Enter a unique Data ID to save this data")

    if st.button("Encrypt and Save"):
        if text and passkey and data_id:
            encrypted_text = encrypt_data(text, passkey)
            hashed_pass = hash_passkey(passkey)
            save_data(data_id, encrypted_text, hashed_pass)
            st.success("Data encrypted and saved successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("Please fill all fields.")

# Decrypt page
def decrypt_page():
    st.title("🔓 Decrypt Your Data")

    data_id = st.text_input("Enter Data ID")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        current_time = time.time()

        # Block user for 30 seconds if 3 failed attempts
        if st.session_state.failed_attempts >= 3 and (current_time - st.session_state.last_attempt_time) < 30:
            st.error("Too many failed attempts. Please wait 30 seconds.")
            return

        if data_id and passkey:
            try:
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)
                st.success("Data decrypted successfully!")
                st.code(decrypted_text, language="text")
                st.session_state.failed_attempts = 0  # Reset on success
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
                st.session_state.failed_attempts += 1
                st.session_state.last_attempt_time = current_time
        else:
            st.error("Please fill all fields.")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Encrypt", "Decrypt"])

if page == "Home":
    home()
elif page == "Encrypt":
    encrypt_page()
elif page == "Decrypt":
    decrypt_page()
