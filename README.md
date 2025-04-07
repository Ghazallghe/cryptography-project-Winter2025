# 🔐 cryptography-project-Winter2025

This project demonstrates a full pipeline of secure client-server communication using a custom PKI (Public Key Infrastructure). It includes custom implementations of **RSA**, **DSA**, **CSR**, **Certificate Authority (CA)**, and a **custom symmetric cipher (Coco128)** to simulate a secure communication lifecycle.

## 📁 Project Structure

```
├── CA/                    # Certificate Authority (offline + online)
├── CERT/                 # Stores signed certificates
├── CSR/                  # Certificate Signing Request (CSR) from client
├── client/               # Client key generation and communication
├── server/               # Server receives client requests and handles secure messaging
├── coco_cipher/          # Custom symmetric cipher: Coco128
├── dsa.py                # DSA key generation and signing
├── my_rsa.py             # RSA implementation (key gen, encrypt/decrypt)
├── utils.py              # Helper functions
└── README.md             # You're here :)
```

## 🧩 Phase 1: Crypto Primitives

Implemented core cryptographic algorithms:

- 🔐 **RSA**: For client-side public/private key pair generation and secure key exchange.
- ✍️ **DSA**: For signing client certificates (used by the CA).
- 🧠 **Custom Cipher (Coco128)**: A custom symmetric encryption algorithm.

## 🧪 Phase 2: Full PKI System + Secure Communication

### 1. 🔑 Key & Certificate Generation
- The **client** generates an RSA key pair and stores them in `.pem` format.
- It prepares a **CSR (Certificate Signing Request)** in JSON format, saved in the `CSR/` directory.

### 2. 🏛️ Certificate Authority (CA)
- The **CA** generates DSA keys and stores them in `.pem` format (`ca_private_key_cert_001.pem`, `ca_public_key_cert_001.pem`).
- It reads the client's CSR, signs the public key using its private DSA key, and produces a certificate stored in the `CERT/` directory.

### 3. 🌐 Secure TCP Communication

The secure connection between **Client** and **Server** follows these steps:

1. Client connects to Server via TCP.
2. Server requests the Client's certificate.
3. Client sends its signed certificate from `CERT/`.
4. Server contacts **CA** to validate the certificate.
5. If valid:
   - Server generates a **symmetric key (RC4)**.
   - Encrypts the key using the client's **RSA public key**.
   - Sends the encrypted key to the client.
6. Client decrypts the key with its **RSA private key**.
7. Client encrypts a message using the **Coco128 cipher** (with IV + encrypted message data).
8. Encrypted data is sent to the Server for processing.
9. If invalid:
   - Server sends ERR and closes the connection

## 🛠️ How to Run

### Prerequisites
- Python 3.10+
- [`cryptography`](https://pypi.org/project/cryptography/) library

### Install Dependencies

```bash
pip install cryptography
```

### Step-by-Step Flow

#### 🧷 Client Side
```bash
python client/offline_client.py  # Generates RSA keys + CSR
```

#### 🏛️ CA Side
```bash
python CA/offline_ca.py          # Generates DSA keys and generates cert
python CA/online_ca.py           # Verifies certification
```

#### 🖥️ Start Server
```bash
python server/server.py
```

#### 🧬 Run Client Communication
```bash
python client/online_client.py
```


## 🔒 Crypto Highlights

- **RSA** for asymmetric encryption & secure key transfer
- **DSA** for digital signatures in certificate authority
- **Custom PKI model** using JSON-based CSRs
- **RC4** as symmetric key (for simplicity)
- **Coco128**: A lightweight symmetric block cipher with custom round functions and S-boxes


## 📂 Sample Certificate (`client_cert_001.json`)

```json
{
  "public_key": "....",
  "signature": "....",
  "client_id": "client_001"
}
```


## 📚 Educational Purpose

This project is built for educational purposes to simulate how secure communication and certificate validation works under the hood, especially in systems like HTTPS, SSL/TLS, and VPNs.
