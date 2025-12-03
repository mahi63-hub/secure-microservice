import base64

def decrypt_seed(encrypted_seed_b64, private_key):
    encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    hex_seed = decrypted_bytes.decode('utf-8')
    
    if len(hex_seed) != 64:
        raise ValueError(f"Seed length is {len(hex_seed)}, expected 64")
    
    valid_chars = set('0123456789abcdef')
    if not all(c in valid_chars for c in hex_seed.lower()):
        raise ValueError("Seed contains invalid hex characters")
    
    return hex_seed

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    
    with open("student_private.pem", "rb") as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()
    
    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
        print(hex_seed)
        
        with open("seed.txt", "w") as f:
            f.write(hex_seed)
            
    except Exception as e:
        print(f"Error: {e}")
