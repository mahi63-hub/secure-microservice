import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

with open("commit_hash.txt", "r") as f:
    commit_hash = f.read().strip()

with open("student_private.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

signature = private_key.sign(
    commit_hash.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

with open("instructor_public.pem", "rb") as f:
    instructor_public_key = load_pem_public_key(f.read(), backend=default_backend())

encrypted_signature = instructor_public_key.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

encrypted_signature_b64 = base64.b64encode(encrypted_signature).decode('utf-8')
print(encrypted_signature_b64)

with open("encrypted_signature.txt", "w") as f:
    f.write(encrypted_signature_b64)
