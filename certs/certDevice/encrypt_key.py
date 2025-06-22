import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def pad_data(data: bytes, block_size: int = 16) -> bytes:
    """Thêm padding PKCS7."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def encrypt_key(key_path: str, output_path: str, passphrase: str):
    # Đọc private key
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Chuyển sang PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Tạo salt và key từ passphrase
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())

    # Mã hóa
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_pem = encryptor.update(pad_data(pem)) + encryptor.finalize()

    # Lưu file
    with open(output_path, "wb") as f:
        f.write(salt + iv + encrypted_pem)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt_key.py <input_key> <output_path> <passphrase>")
        sys.exit(1)
    
    encrypt_key(sys.argv[1], sys.argv[2], sys.argv[3])