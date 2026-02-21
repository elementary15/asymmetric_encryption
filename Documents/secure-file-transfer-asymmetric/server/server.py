import socket
import os
import sys

# --- PATH INJECTION ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives import serialization
from common.crypto_utils import (
    load_private_key,
    rsa_decrypt_key,
    aes_decrypt,
    verify_signature
)
from common.merkle import read_file_chunks, build_merkle_root

# --- CONFIGURATION ---
HOST = "127.0.0.1" 
PORT = 61234
ADDR = (HOST, PORT)
STORAGE_DIR = "server_storage"
# Fixed path to match your actual folder structure
PRIVATE_KEY_PATH = "keys/server_private.pem"

# --- PROTOCOL CONSTANTS ---
FILENAME_LEN_BYTES = 2
AES_KEY_LEN_BYTES = 4
FILE_SIZE_LEN_BYTES = 8
IV_SIZE_BYTES = 16
MERKLE_ROOT_BYTES = 64
SIG_LEN_PREFIX_BYTES = 4

os.makedirs(STORAGE_DIR, exist_ok=True)

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection lost")
        data += packet
    return data

def handle_client(conn, addr, private_key):
    try:
        # 0. Receive and sanitize filename
        raw_name_len = conn.recv(FILENAME_LEN_BYTES)
        if not raw_name_len: return
        name_len = int.from_bytes(raw_name_len, "big")
        filename_str = recv_exact(conn, name_len).decode()
        
        # Security Fix
        filename_str = os.path.basename(filename_str)

        # 1. Receive encrypted AES key
        raw_key_len = conn.recv(AES_KEY_LEN_BYTES)
        key_len = int.from_bytes(raw_key_len, "big")
        encrypted_key = recv_exact(conn, key_len)

        # 2. Receive IV
        iv = recv_exact(conn, IV_SIZE_BYTES)

        # 3. Receive encrypted data
        raw_file_size = conn.recv(FILE_SIZE_LEN_BYTES)
        file_size = int.from_bytes(raw_file_size, "big")
        encrypted_data = recv_exact(conn, file_size)

        # 4. Receive Merkle root
        merkle_root = recv_exact(conn, MERKLE_ROOT_BYTES).decode()

        # 5. Receive Client Auth Data
        pub_len = int.from_bytes(conn.recv(SIG_LEN_PREFIX_BYTES), "big")
        client_public_key_bytes = recv_exact(conn, pub_len)
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

        sig_len = int.from_bytes(conn.recv(SIG_LEN_PREFIX_BYTES), "big")
        signature = recv_exact(conn, sig_len)

        # 6. Decrypt and Save
        aes_key = rsa_decrypt_key(encrypted_key, private_key)
        plaintext = aes_decrypt(aes_key, iv, encrypted_data)

        filepath = os.path.join(STORAGE_DIR, filename_str)
        with open(filepath, "wb") as f:
            f.write(plaintext)

        # 7. Verification Steps
        chunks = read_file_chunks(filepath)
        computed_root = build_merkle_root(chunks)

        # Verify Signature
        if not verify_signature(merkle_root.encode(), signature, client_public_key):
            print(f"Security Alert: Invalid signature from {addr}")
            conn.send(b"SIGNATURE_INVALID")
            return

        # Verify Merkle Integrity
        if computed_root == merkle_root:
            print(f"Success: Verified and Saved {filename_str}")
            conn.send(b"OK")
        else:
            print(f"Failure: Integrity mismatch for {filename_str}")
            conn.send(b"INTEGRITY_FAIL")

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
        try: conn.send(b"ERROR")
        except: pass
    finally:
        conn.close()

def main():
    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"Error: Server private key not found at {PRIVATE_KEY_PATH}")
        return

    private_key = load_private_key(PRIVATE_KEY_PATH)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)
    server.listen(5)
    print(f"Server listening on {ADDR}...")

    while True:
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        handle_client(conn, addr, private_key)

if __name__ == "__main__":
    main()