# 🛡️ Secure File Transfer System (Asymmetric Cryptography)

A professional-grade secure client–server file transfer system implementing **asymmetric encryption, hybrid cryptography, Merkle tree integrity verification, and digital signatures**. 

This project demonstrates a robust, real-world secure protocol design, moving beyond "toy" encryption to handle binary-safe transfers and verifiable authenticity.

---

## ✨ Features

- **Asymmetric Key Exchange**: Uses **RSA (OAEP)** for secure session key distribution.
- **Hybrid Cryptography**: High-performance bulk encryption using **AES-256 (CBC)**.
- **Merkle Tree Integrity**: Complete file verification using **SHA-256** Merkle proofs.
- **Sender Authentication**: Non-repudiation via **RSA-PSS Digital Signatures**.
- **Custom Socket Protocol**: Binary-safe, length-prefixed protocol to prevent data corruption.
- **Modern UI**: Streamlit-based web interface for easy client uploads.
- **Modular Architecture**: Clean separation between cryptographic primitives, protocol logic, and UI layers.

---

## 🏗️ High-Level Architecture



### The Workflow:
1. **Client**: 
   - Computes the Merkle Root of the source file.
   - Signs the Merkle Root using the **Client Private Key**.
   - Encrypts the file using a one-time **AES-256** session key.
   - Encrypts that AES key using the **Server Public Key**.
   - Transmits the encrypted payload, signature, and client public key.

2. **Server**: 
   - Decrypts the AES key using the **Server Private Key**.
   - Decrypts the file data.
   - Recomputes the Merkle Root from the decrypted data.
   - Verifies the digital signature using the **Client Public Key**.
   - Accepts the file only if **Integrity** and **Authenticity** checks pass.

---

## 🔐 Cryptographic Design

### Hybrid Encryption
- **RSA** is utilized solely for encrypting the AES session key to avoid RSA's inherent size limitations.
- **AES-256** handles the heavy lifting of file data encryption for maximum performance.

### Integrity Verification

- Files are split into equal chunks.
- Each chunk is hashed; hashes are recursively combined to form a **Merkle Tree**.
- The resulting **Merkle Root** serves as a unique fingerprint for the entire file.

### Digital Signatures
- The client signs the **Merkle Root** rather than the raw file, ensuring efficiency even for large files.
- Employs **RSA-PSS with SHA-256** to prevent impersonation.

---

## 🛡️ Threat Model & Protections

| Threat | Mitigation |
| :--- | :--- |
| **Man-in-the-Middle** | RSA-encrypted AES session key exchange |
| **Data Tampering** | Merkle tree integrity verification (SHA-256) |
| **Sender Impersonation** | RSA-PSS digital signatures (Authenticity) |
| **Replay Attacks** | Signature bound to unique file hash |
| **Unauthorized Modification** | Independent server-side hash recomputation |

---

## 📂 Project Structure

```text
secure-file-transfer-asymmetric/
│
├── client/
│   ├── client.py        # Core client protocol logic
│   └── app.py           # Streamlit Web UI
│
├── server/
│   └── server.py        # Secure server implementation
│
├── common/
│   ├── crypto_utils.py  # Shared Encryption & Signature utilities
│   └── merkle.py        # Merkle tree implementation
│
├── keys/                # RSA Key pairs (Gitignored)
├── server_storage/      # Secure vault for received files
├── requirements.txt     # Project dependencies
└── README.md            # Documentation


