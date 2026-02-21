import socket
import os
import sys

# --- PATH INJECTION ---
# Ensures 'common' can be found when running from the 'client' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives import serialization
from common.crypto_utils import (
    load_public_key,
    aes_encrypt,
    rsa_encrypt_key,
    sign_data
)
from common.merkle import read_file_chunks, build_merkle_root

# --- CONFIGURATION ---
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 61234
ADDR = (SERVER_HOST, SERVER_PORT)
# Corrected path based on your file tree
PUBLIC_KEY_PATH = "keys/server_public.pem" 

# --- PROTOCOL CONSTANTS ---
FILENAME_LEN_BYTES = 2
AES_KEY_LEN_BYTES = 4
FILE_SIZE_LEN_BYTES = 8
SIG_LEN_PREFIX_BYTES = 4 

def send_file(file_path):
    if not os.path.exists(PUBLIC_KEY_PATH):
        return "SERVER_PUBLIC_KEY_MISSING"

    try:
        # Corrected paths to match your root keys folder
        with open("keys/client_private.pem", "rb") as f:
            client_private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open("keys/client_public.pem", "rb") as f:
            client_public_key_bytes = f.read()
    except FileNotFoundError:
        return "CLIENT_KEYS_MISSING"

    server_public_key = load_public_key(PUBLIC_KEY_PATH)

    with open(file_path, "rb") as f:
        data = f.read()

    chunks = read_file_chunks(file_path)
    merkle_root = build_merkle_root(chunks)
    signature = sign_data(merkle_root.encode(), client_private_key)

    aes_key, iv, ciphertext = aes_encrypt(data)
    encrypted_key = rsa_encrypt_key(aes_key, server_public_key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(ADDR)

        # 0. Send Filename
        filename = os.path.basename(file_path).encode()
        sock.send(len(filename).to_bytes(FILENAME_LEN_BYTES, "big"))
        sock.send(filename)

        # 1. Send encrypted AES key
        sock.send(len(encrypted_key).to_bytes(AES_KEY_LEN_BYTES, "big"))
        sock.sendall(encrypted_key)

        # 2. Send IV
        sock.sendall(iv)

        # 3. Send encrypted file
        sock.send(len(ciphertext).to_bytes(FILE_SIZE_LEN_BYTES, "big"))
        sock.sendall(ciphertext)

        # 4. Send Merkle root
        sock.sendall(merkle_root.encode())

        # 5. Send client public key
        sock.send(len(client_public_key_bytes).to_bytes(SIG_LEN_PREFIX_BYTES, "big"))
        sock.sendall(client_public_key_bytes)

        # 6. Send Signature
        sock.send(len(signature).to_bytes(SIG_LEN_PREFIX_BYTES, "big"))
        sock.sendall(signature)

        response = sock.recv(1024).decode()
        return response

    except ConnectionRefusedError:
        return "CONNECTION_FAILED"
    except Exception as e:
        return f"ERROR: {str(e)}"
    finally:
        sock.close()

def upload_file(file_path: str) -> str:
    if not os.path.exists(file_path):
        return "FILE_NOT_FOUND"
    return send_file(file_path)