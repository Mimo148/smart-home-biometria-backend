from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(BASE_DIR, "keys")

os.makedirs(KEY_DIR, exist_ok=True)

# generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# save private key
with open(os.path.join(KEY_DIR, "private.pem"), "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# save public key
public_key = private_key.public_key()
with open(os.path.join(KEY_DIR, "public.pem"), "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Keys saved in keys/ directory")
