import sys
import json
import base64
import binascii
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from datetime import datetime

def verify_certificate(cert_hex, ca_cert_pem):
    try:
        clean_cert = ''.join(filter(lambda x: x in '0123456789abcdefABCDEF', cert_hex))
        if len(clean_cert) != 1040:
            return {"status": "error", "message": f"Certificate length incorrect: expected 1040, got {len(clean_cert)}"}

        cert_bytes = binascii.unhexlify(clean_cert)
        if len(cert_bytes) != 520:
            return {"status": "error", "message": f"Certificate bytes length incorrect: expected 520, got {len(cert_bytes)}"}

        cert_pem = f"-----BEGIN CERTIFICATE-----\n{base64.b64encode(cert_bytes).decode('ascii')}\n-----END CERTIFICATE-----"
        cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('ascii'), default_backend())

        ca_public_key = ca_cert.public_key()
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return {"status": "error", "message": "Unsupported CA public key type"}

        if cert.issuer != ca_cert.subject:
            return {"status": "error", "message": "Certificate issuer does not match CA subject"}

        now = datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            return {"status": "error", "message": "Certificate is not valid at current time"}

        return {
            "status": "success",
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat()
        }
    except InvalidSignature:
        return {"status": "error", "message": "Certificate verification failed: invalid signature"}
    except Exception as e:
        return {"status": "error", "message": f"Error verifying certificate: {str(e)}"}

def compute_shared_secret(pub_key_x, pub_key_y):
    try:
        if not pub_key_x or not pub_key_y:
            return {"status": "error", "message": "Public key coordinates cannot be empty"}
        if len(pub_key_x) != 64 or len(pub_key_y) != 64:
            return {"status": "error", "message": f"Invalid public key length: X={len(pub_key_x)}, Y={len(pub_key_y)}"}
        if not all(c in '0123456789abcdefABCDEF' for c in pub_key_x + pub_key_y):
            return {"status": "error", "message": f"Invalid public key format: X={pub_key_x[:10]}..., Y={pub_key_y[:10]}..."}

        try:
            x_int = int(pub_key_x, 16)
            y_int = int(pub_key_y, 16)
        except ValueError:
            return {"status": "error", "message": f"Invalid hex values: X={pub_key_x[:10]}..., Y={pub_key_y[:10]}..."}

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        server_pub_key = private_key.public_key()
        server_pub_numbers = server_pub_key.public_numbers()
        server_pub_x = format(server_pub_numbers.x, '064x')
        server_pub_y = format(server_pub_numbers.y, '064x')

        try:
            client_pub_numbers = ec.EllipticCurvePublicNumbers(
                x_int,
                y_int,
                ec.SECP256R1()
            )
            client_pub_key = client_pub_numbers.public_key(default_backend())
        except ValueError as e:
            return {"status": "error", "message": f"Failed to create public key: {str(e)}"}

        shared_secret = private_key.exchange(ec.ECDH(), client_pub_key)
        return {
            "status": "success",
            "shared_secret": shared_secret.hex(),
            "server_pub_key_x": server_pub_x,
            "server_pub_key_y": server_pub_y
        }
    except Exception as e:
        return {"status": "error", "message": f"Error computing shared secret: {str(e)}"}

# def decrypt_data(ciphertext, tag, nonce, shared_secret):
    try:
        # Validate input types and formats
        if not isinstance(ciphertext, str) or not ciphertext or not all(c in '0123456789abcdefABCDEF' for c in ciphertext):
            return {"status": "error", "message": f"Invalid ciphertext: must be a non-empty hexadecimal string, got '{ciphertext[:10]}...'"}
        if not isinstance(tag, str) or len(tag) != 32 or not all(c in '0123456789abcdefABCDEF' for c in tag):
            return {"status": "error", "message": f"Invalid tag: must be a 32-character hexadecimal string, got length {len(tag)}"}
        if not isinstance(nonce, str) or len(nonce) != 24 or not all(c in '0123456789abcdefABCDEF' for c in nonce):
            return {"status": "error", "message": f"Invalid nonce: must be a 24-character hexadecimal string, got length {len(nonce)}"}
        if not isinstance(shared_secret, str) or len(shared_secret) != 64 or not all(c in '0123456789abcdefABCDEF' for c in shared_secret):
            return {"status": "error", "message": f"Invalid shared secret: must be a 64-character hexadecimal string, got length {len(shared_secret)}"}

        # Convert hex to bytes
        try:
            ciphertext_bytes = binascii.unhexlify(ciphertext)
            tag_bytes = binascii.unhexlify(tag)
            nonce_bytes = binascii.unhexlify(nonce)
            key = binascii.unhexlify(shared_secret)
        except binascii.Error as e:
            return {"status": "error", "message": f"Hex decoding error: {str(e)} (ciphertext={ciphertext[:10]}..., tag={tag}, nonce={nonce}, shared_secret={shared_secret[:10]}...)"}

        # Validate key length
        if len(key) != 32:
            return {"status": "error", "message": f"Invalid shared secret: must be 32 bytes, got {len(key)}"}

        # Pad nonce to 16 bytes (128 bits) to satisfy cryptography's ChaCha20 requirement
        if len(nonce_bytes) == 12:
            # Pad with 4 zero bytes at the end (common for ChaCha20 compatibility)
            nonce_bytes = nonce_bytes + b'\x00\x00\x00\x00'
        elif len(nonce_bytes) != 16:
            return {"status": "error", "message": f"Invalid nonce length after decoding: must be 12 or 16 bytes, got {len(nonce_bytes)}"}

        # Decrypt using ChaCha20-Poly1305
        try:
            cipher = Cipher(algorithms.ChaCha20(key, nonce_bytes), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            # Combine ciphertext and tag for decryption, as Node.js does
            decrypted = decryptor.update(ciphertext_bytes + tag_bytes)
        except Exception as e:
            return {"status": "error", "message": f"ChaCha20 decryption error: {str(e)}"}

        # Attempt to decode and parse as JSON
        try:
            result = json.loads(decrypted.decode('utf-8'))
            return {
                "status": "success",
                "decrypted_data": result
            }
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # Return raw decrypted bytes as hex for debugging
            return {
                "status": "error",
                "message": f"Failed to decode or parse decrypted data: {str(e)}",
                "decrypted_hex": decrypted.hex()
            }
    except Exception as e:
        return {"status": "error", "message": f"Decryption error: {str(e)}"}

if __name__ == "__main__":
    try:
        action = sys.argv[1]
        if action == "verify_certificate" and len(sys.argv) >= 4:
            cert_hex, ca_cert_pem = sys.argv[2:4]
            result = verify_certificate(cert_hex, ca_cert_pem)
        elif action == "compute_shared_secret" and len(sys.argv) >= 4:
            pub_key_x, pub_key_y = sys.argv[2:4]
            result = compute_shared_secret(pub_key_x, pub_key_y)
        # elif action == "decrypt_data" and len(sys.argv) >= 6:
        #     # Use only the first set of arguments to handle duplicates
        #     ciphertext, tag, nonce, shared_secret = sys.argv[2:6]
        #     result = decrypt_data(ciphertext, tag, nonce, shared_secret)
        else:
            result = {"status": "error", "message": f"Invalid action or insufficient arguments: action={action}, args={sys.argv[2:]}"}
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"status": "error", "message": f"Script error: {str(e)}, args={sys.argv}"}))