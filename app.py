import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate Fernet cipher
if "cipher_key" not in st.session_state:
    st.session_state.cipher_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.cipher_key)

# In-memory secure data store
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": "...", "passkey": "hashed"}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = True

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Reauthorization (Login) page
def login_page():
    st.subheader("🔑 Reauthorization Required")
    password = st.text_input("Enter Admin Password:", type="password")
    if st.button("Login"):
        if password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Access granted! Returning to Retrieve Page...")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid password")

# Home page
def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("Use this app to **securely store and retrieve encrypted data** with passkey protection.")

# Store Data page
def store_data_page():
    st.subheader("📂 Store Data")
    data = st.text_area("Enter the data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted = encrypt_data(data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored securely!")
            st.code(encrypted)
        else:
            st.warning("⚠️ Please enter both data and passkey.")

# Retrieve Data page
def retrieve_data_page():
    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts! Please login.")
        st.session_state.reauthorized = False
        login_page()
        return

    if not st.session_state.reauthorized:
        login_page()
        return

    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter encrypted text:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result)
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect! {attempts_left} attempt(s) left.")
        else:
            st.warning("⚠️ Both fields are required.")

# Sidebar Navigation
st.sidebar.title("🔒 Navigation")
choice = st.sidebar.radio("Go to", ["Home", "Store Data", "Retrieve Data", "Login"])

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
elif choice == "Login":
    login_page()