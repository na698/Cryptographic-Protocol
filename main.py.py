from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# === Step 1: RSA Key Generation ===
def generate_rsa_keys():
    """Generate RSA key pair for secure AES key exchange."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# === Step 2: AES Key Generation and Secure Sharing ===
def encrypt_aes_key(public_key, aes_key):
    """Encrypt AES key using recipient's RSA public key."""
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_aes_key(private_key, encrypted_key):
    """Decrypt AES key using recipient's RSA private key."""
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# === Step 3: ECDSA Key Generation and Signing ===
def generate_ecdsa_keys():
    """Generate ECDSA key pair for digital signature."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_contract(private_key, contract):
    """Sign contract using ECDSA private key."""
    return private_key.sign(contract, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, signature, contract):
    """Verify ECDSA signature."""
    try:
        public_key.verify(signature, contract, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# === Step 4: Protocol Execution ===
def main():
    print("\n📘 Cryptographic Protocol Simulation Started")

    # Parties generate RSA keys
    solicitor_private, solicitor_public = generate_rsa_keys()
    hr_private, hr_public = generate_rsa_keys()

    # AES key generation and secure exchange
    aes_key = Fernet.generate_key()
    encrypted_aes_key = encrypt_aes_key(solicitor_public, aes_key)
    decrypted_aes_key = decrypt_aes_key(solicitor_private, encrypted_aes_key)
    print("\n🔐 AES Key securely exchanged")

    # Contract encryption
    contract = b"This is the contract between Mrs. Harvey and Mr. Facey."
    cipher = Fernet(decrypted_aes_key)
    encrypted_contract = cipher.encrypt(contract)
    print("\n📄 Encrypted Contract:", encrypted_contract)

    # ECDSA signing
    ecdsa_private, ecdsa_public = generate_ecdsa_keys()
    signature = sign_contract(ecdsa_private, contract)
    print("\n🖋️ Signature:", signature)

    # Decryption and verification
    decrypted_contract = cipher.decrypt(encrypted_contract)
    print("\n📄 Decrypted Contract:", decrypted_contract.decode())

    if verify_signature(ecdsa_public, signature, decrypted_contract):
        print("\n✅ Signature is valid. Contract accepted.")
    else:
        print("\n❌ Signature is invalid. Contract rejected.")

    print("\n📘 Protocol Completed Successfully")

# === Run the Protocol ===
if __name__ == "__main__":
    main()
