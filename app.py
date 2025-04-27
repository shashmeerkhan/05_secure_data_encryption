import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Secure fixed key (you can generate once using Fernet.generate_key())
KEY = b'kICqsZRVxv6f4FrJhNa-6RMFlQeC0wKDWj1jZaXXbGo='  # Replace with your own fixed key
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: {encrypted_text: {"encrypted_text": ..., "passkey": hashed_passkey}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data (with passkey check)
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for data in stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔐 Secure Data Storage App")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Use this app to **securely store** and **retrieve** data using passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Your Data")
    user_data = st.text_area("Enter data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please provide both data and passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Please reauthorize to continue.")
        st.stop()

    st.subheader("🔍 Retrieve Stored Data")
    encrypted_text = st.text_area("Enter encrypted data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Data decrypted successfully!")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("⚠️ Too many failed attempts! Redirecting to login...")
                    st.session_state.authorized = False
                    st.rerun()
        else:
            st.error("⚠️ Please provide both encrypted text and passkey.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized! Redirecting to Retrieve Data page...")
            st.rerun()
        else:
            st.error("❌ Incorrect master password.")
