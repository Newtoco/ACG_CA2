import socket
import json
import base64
import os
import sys

# --- PATH FIX: Allow importing from sibling 'utils' folder ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from utils import crypto_utils as crypto

HOST = '127.0.0.1'
PORT = 65432
KEYS_DIR = os.path.join(parent_dir, "keys")

def upload_file(filename):
    if not os.path.exists(filename):
        print("File not found.")
        return

    print("--- Starting Secure Upload ---")
    
    try:
        client_private_key = crypto.load_private_key(os.path.join(KEYS_DIR, "client_private.pem"))
        server_public_key = crypto.load_public_key(os.path.join(KEYS_DIR, "server_public.pem"))
    except FileNotFoundError:
        print("❌ Keys not found! Did you run 'utils/keygen.py'?")
        return

    # 1. Read File
    with open(filename, "rb") as f:
        file_data = f.read()

    # 2. Encrypt & Sign
    aes_key = crypto.generate_aes_key()
    ciphertext = crypto.encrypt_file_aes(file_data, aes_key)
    signature = crypto.sign_data(ciphertext, client_private_key)
    enc_aes_key = crypto.encrypt_aes_key_rsa(aes_key, server_public_key)

    # 3. Prepare Packet
    metadata = {
        "filename": os.path.basename(filename),
        "enc_aes_key": base64.b64encode(enc_aes_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    json_data = json.dumps(metadata).encode('utf-8')
    
    # 4. Send
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            s.sendall(len(json_data).to_bytes(4, byteorder='big'))
            s.sendall(json_data)
            print(f"Server Response: {s.recv(1024).decode()}")
        except ConnectionRefusedError:
            print("❌ Could not connect to server.")

if __name__ == "__main__":
    file_to_upload = input("Enter filename to upload: ")
    upload_file(file_to_upload)