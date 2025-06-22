import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def unpad_data(data: bytes) -> bytes:
    """Xóa padding PKCS7."""
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_key(encrypted_path: str, passphrase: str) -> str:
    # Đọc file mã hóa
    with open(encrypted_path, "rb") as f:
        data = f.read()
        salt, iv, encrypted_pem = data[:16], data[16:32], data[32:]

    # Tạo key từ passphrase
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())

    # Giải mã
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_pem = unpad_data(decryptor.update(encrypted_pem) + decryptor.finalize())

    return decrypted_pem.decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decrypt_key.py <encrypted_key> <passphrase>")
        sys.exit(1)
    
    print(decrypt_key(sys.argv[1], sys.argv[2]))