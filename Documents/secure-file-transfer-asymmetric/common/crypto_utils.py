from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as sig_padding

import os

# ---------- KEY LOADING ----------

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

# ---------- SYMMETRIC (AES) ----------

def aes_encrypt(data: bytes):
    key = os.urandom(32)      # AES-256
    iv = os.urandom(16)       # CBC IV

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    # PKCS7 padding (manual, intentional)
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return key, iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len]

# ---------- ASYMMETRIC (RSA) ----------

def rsa_encrypt_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------- DIGITAL SIGNATURES ----------

def sign_data(data: bytes, private_key):
    signature = private_key.sign(
        data,
        sig_padding.PSS(
            mgf=sig_padding.MGF1(hashes.SHA256()),
            salt_length=sig_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            sig_padding.PSS(
                mgf=sig_padding.MGF1(hashes.SHA256()),
                salt_length=sig_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False