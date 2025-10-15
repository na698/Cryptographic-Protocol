# 📘 Cryptographic Protocol Design Report

##  Introduction

This report presents a secure cryptographic protocol for exchanging legal contracts between parties involved in a property transaction. The protocol simulates a real-world scenario involving Hackit & Run LLP (H&R), Mrs. Harvey (the buyer), and the seller's solicitor. It ensures confidentiality, authenticity, integrity, and non-repudiation using a combination of RSA, AES, and ECDSA algorithms.

---

## 🔄 Protocol Overview

The protocol facilitates secure communication and contract exchange between three parties:

- **H&R**: The buyer’s solicitor  
- **Seller’s Solicitor**: Represents Mr. Facey (the seller)  
- **Mrs. Harvey**: The buyer  

### Communication Flow:
1. H&R and the seller’s solicitor exchange RSA keys.
2. H&R encrypts an AES key using the solicitor’s RSA public key.
3. The solicitor decrypts the AES key using their RSA private key.
4. The contract is encrypted using AES.
5. Mrs. Harvey signs the contract using her ECDSA private key.
6. The signed contract is sent to the solicitor.
7. The solicitor decrypts the contract and verifies the signature.

---

## 🛠️ Implementation Summary

### Step 1: RSA Key Exchange
- RSA keys are generated for both H&R and the seller’s solicitor.
- The AES key is encrypted using RSA with OAEP padding.

### Step 2: AES Encryption
- AES key is generated using Fernet (which includes HMAC).
- The contract is encrypted using this AES key.

### Step 3: ECDSA Signature
- Mrs. Harvey generates an ECDSA key pair.
- She signs the contract using her private key.

### Step 4: Signature Verification
- The solicitor decrypts the contract.
- The signature is verified using Mrs. Harvey’s public key.

---

##  Security Analysis

| Security Goal     | Technique Used                           | Benefit                                                        |
|-------------------|------------------------------------------|------------------------------------------------------------   |
| Confidentiality   | AES (Fernet), RSA key exchange           | Prevents unauthorized access to contract contents                                           |
| Integrity         | HMAC (Fernet), SHA-256                   | Detects tampering and ensures content fidelity                                       |
| Authenticity      | ECDSA signature                          | Confirms the sender’s identity                                                       | 
| Non-Repudiation   | ECDSA + public key verification          | Legally binds the sender to the signed document                                            |
| Key Exchange      | RSA with OAEP padding                    | Securely shares AES key over untrusted channels                                             |



