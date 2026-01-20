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
# Store files inside the Server folder
STORAGE_DIR = os.path.join(current_dir, "server_vault")
# Locate keys in the root 'keys' folder
KEYS_DIR = os.path.join(parent_dir, "keys")

def start_server():
    print(f"Loading keys from: {KEYS_DIR}")
    server_private_key = crypto.load_private_key(os.path.join(KEYS_DIR, "server_private.pem"))
    client_public_key = crypto.load_public_key(os.path.join(KEYS_DIR, "client_public.pem"))

    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"🔒 Secure Vault Server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            
            # 1. Receive Metadata Length
            data_len = conn.recv(4)
            if not data_len: return
            json_len = int.from_bytes(data_len, byteorder='big')
            
            # 2. Receive JSON Metadata
            json_data = conn.recv(json_len).decode('utf-8')
            metadata = json.loads(json_data)
            
            print(f"Receiving file: {metadata['filename']}")
            
            enc_aes_key = base64.b64decode(metadata['enc_aes_key'])
            signature = base64.b64decode(metadata['signature'])
            ciphertext = base64.b64decode(metadata['ciphertext'])
            
            # A. Decrypt AES Key
            try:
                aes_key = crypto.decrypt_aes_key_rsa(enc_aes_key, server_private_key)
                print("✅ AES Key Decrypted.")
            except Exception as e:
                print(f"❌ Failed to decrypt AES key: {e}")
                return

            # B. Verify Signature
            if crypto.verify_signature(ciphertext, signature, client_public_key):
                print("✅ Signature Verified.")
            else:
                print("❌ Signature Failed!")
                return

            # C. Save File
            try:
                decrypted_data = crypto.decrypt_file_aes(ciphertext, aes_key)
                save_path = os.path.join(STORAGE_DIR, metadata['filename'])
                
                with open(save_path, "wb") as f:
                    f.write(decrypted_data)
                    
                print(f"✅ File saved to {save_path}")
                conn.sendall(b"UPLOAD_SUCCESS")
                
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
                conn.sendall(b"UPLOAD_FAIL")

if __name__ == "__main__":
    start_server()