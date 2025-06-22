import json
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

def generate_device_cert(device_id, ca_cert_path="ca-cert.pem", ca_key_path="ca-key.pem"):
    try:
        # Load CA certificate
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load CA private key
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        # Generate device private key (ECDSA secp256r1)
        device_private_key = ec.generate_private_key(ec.SECP256R1())
        device_public_key = device_private_key.public_key()

        # Create CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Giangvo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyIoT"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IoT"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"ESP32_Sensor"),
        ]))
        csr = builder.sign(device_private_key, hashes.SHA256())

        # Calculate Subject Key Identifier
        pub_bytes = device_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ski = x509.SubjectKeyIdentifier.from_public_key(device_public_key)

        # Calculate Authority Key Identifier
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())

        # Sign CSR to create device certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
        builder = builder.add_extension(ski, critical=False)
        builder = builder.add_extension(aki, critical=False)
        device_cert = builder.sign(ca_key, hashes.SHA256())

        # Convert certificate to DER and then to hex
        device_cert_der = device_cert.public_bytes(serialization.Encoding.DER)
        device_cert_hex = device_cert_der.hex()

        # Convert private key to DER without optional public key
        device_private_key_der = device_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # Use ECPrivateKey format
            encryption_algorithm=serialization.NoEncryption()
        )
        device_private_key_hex = device_private_key_der.hex()

        # Get serial number in hex format
        serial_number = format(device_cert.serial_number, 'X')

        # Generate expiry date (ISO 8601 format)
        expiry = device_cert.not_valid_after.isoformat()

        return {
            "device_id": device_id,
            "certificate": device_cert_hex,
            "private_key": device_private_key_hex,
            "serial": serial_number,  
            "expiry": expiry
        }

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(json.dumps({"error": "Device ID, CA certificate path and CA key path are required"}))
        sys.exit(1)

    device_id = sys.argv[1]
    ca_cert_path = sys.argv[2]
    ca_key_path = sys.argv[3]
    
    try:
        result = generate_device_cert(device_id, ca_cert_path, ca_key_path)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)