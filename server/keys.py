import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIR = "keys"
PRIVATE_KEY = "private.pem"
PUBLIC_KEY = "public.pem"


def generate_and_save_keys():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate RSA public key
    public_key = private_key.public_key()

    # Serialize private key with PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key with PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create directory if it does not exist
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Save the private key
    with open(os.path.join(KEYS_DIR, PRIVATE_KEY), 'wb') as f:
        f.write(pem_private)

    # Save the public key
    with open(os.path.join(KEYS_DIR, PUBLIC_KEY), 'wb') as f:
        f.write(pem_public)

    print(f"Generated new public-private key pair.\n")


if __name__ == '__main__':
    generate_and_save_keys()
