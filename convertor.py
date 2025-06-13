import base64
import hashlib
import os
from Crypto.Cipher import AES
import pyttsx3
import streamlit as st

# AES encryption function
def encrypt_aes(message, password, mode_option):
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)

    if mode_option == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode_option == "CFB":
        cipher = AES.new(key, AES.MODE_CFB, iv)
    elif mode_option == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv)
    else:  # fallback
        cipher = AES.new(key, AES.MODE_CBC, iv)

    pad_len = 16 - len(message.encode()) % 16
    padded = message.encode() + bytes([pad_len] * pad_len)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

# AES decryption function
def decrypt_aes(cipher_text_b64, password, mode_option):
    try:
        cipher_text = base64.b64decode(cipher_text_b64)
        key = hashlib.sha256(password.encode()).digest()
        iv = cipher_text[:16]

        if mode_option == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif mode_option == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
        elif mode_option == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted = cipher.decrypt(cipher_text[16:])
        pad_len = decrypted[-1]
        message = decrypted[:-pad_len].decode('utf-8')
        return message
    except Exception as e:
        return f"[ERROR] Decryption failed: {str(e)}"

# Text-to-Speech function
def speak_message(message):
    engine = pyttsx3.init()
    engine.say(message)
    engine.runAndWait()

# Streamlit UI
def main():
    st.set_page_config(page_title="AES Audio Tool", page_icon="🔐", layout="centered")

    st.title("🔐 AES Audio Encryption & Decryption")
    st.markdown("""
    Select an option below to either encrypt a secret message or decrypt an existing AES message.
    """)

    choice = st.radio("Choose your action:", ("🔒 Encrypt a message", "🔓 Decrypt a message"))
    mode_option = st.selectbox("Select AES Mode", ("CBC", "CFB", "OFB"))

    if choice == "🔒 Encrypt a message":
        st.subheader("🔒 Encrypt a Message")
        message = st.text_area("Enter your message", height=150)
        password = st.text_input("Set a password", type="password")
        if st.button("🔐 Encrypt"):
            if not message.strip() or not password:
                st.warning("Please enter both message and password.")
            else:
                encrypted = encrypt_aes(message.strip(), password, mode_option)
                st.success("Encryption Successful! 🔐")
                st.text_area("📤 Encrypted Output (Base64)", encrypted, height=100)

    elif choice == "🔓 Decrypt a message":
        st.subheader("🔓 Decrypt a Message")
        cipher_text_b64 = st.text_area("📥 Encrypted Message (Base64)", height=150)
        password = st.text_input("🔑 Password", type="password")

        if st.button("🔓 Decrypt"):
            if not cipher_text_b64.strip() or not password:
                st.warning("Please provide both encrypted message and password.")
            else:
                message = decrypt_aes(cipher_text_b64.strip(), password, mode_option)
                if message.startswith("[ERROR]"):
                    st.error(message)
                else:
                    st.success("Decryption Successful! 🎉")
                    st.text_area("📤 Decrypted Message", message, height=100, key="decrypted_output")
                    st.session_state['decrypted_message'] = message

        if 'decrypted_message' in st.session_state:
            if st.button("🔊 Play Message Audio"):
                speak_message(st.session_state['decrypted_message'])

if __name__ == "__main__":
    main()