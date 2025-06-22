import json
import sys
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

def verify_certificate(cert_hex, private_key_hex, ca_cert_path):
       try:
           # Convert hex to bytes
           cert_der = bytes.fromhex(cert_hex)
           private_key_der = bytes.fromhex(private_key_hex)

           # Load certificate
           cert = x509.load_der_x509_certificate(cert_der)

           # Load private key
           private_key = serialization.load_der_private_key(private_key_der, password=None)

           # Load CA certificate
           with open(ca_cert_path, "rb") as f:
               ca_cert = x509.load_pem_x509_certificate(f.read())

           # Step 1: Check certificate validity period
           current_time = datetime.utcnow()
           if cert.not_valid_before > current_time:
               raise ValueError("Certificate is not yet valid")
           if cert.not_valid_after < current_time:
               raise ValueError("Certificate has expired")

           # Step 2: Verify private key matches certificate's public key
           cert_public_key = cert.public_key()
           private_key_public = private_key.public_key()
           cert_pub_bytes = cert_public_key.public_bytes(
               encoding=serialization.Encoding.DER,
               format=serialization.PublicFormat.SubjectPublicKeyInfo
           )
           priv_pub_bytes = private_key_public.public_bytes(
               encoding=serialization.Encoding.DER,
               format=serialization.PublicFormat.SubjectPublicKeyInfo
           )
           if cert_pub_bytes != priv_pub_bytes:
               raise ValueError("Private key does not match certificate's public key")

           # Step 3: Verify CA signature
           ca_public_key = ca_cert.public_key()
           ca_public_key.verify(
               cert.signature,
               cert.tbs_certificate_bytes,
               ec.ECDSA(hashes.SHA256()) if isinstance(ca_public_key, ec.EllipticCurvePublicKey) else None
           )

           # Step 4: Check extensions
           try:
               cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
           except x509.ExtensionNotFound:
               print("Warning: Subject Key Identifier extension not found", file=sys.stderr)
           
           try:
               cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
           except x509.ExtensionNotFound:
               print("Warning: Authority Key Identifier extension not found", file=sys.stderr)

           # Step 5: Verify certificate subject
           expected_subject = {
               "country_name": "VN",
               "state_or_province_name": "Hanoi",
               "locality_name": "Giangvo",
               "organization_name": "MyIoT",
               "organizational_unit_name": "IoT",
               "common_name": "ESP32_Sensor"
           }
           subject = cert.subject
           subject_dict = {attr.oid: attr.value for attr in subject}
           for key, value in expected_subject.items():
               oid = getattr(x509.NameOID, key.upper())
               if subject_dict.get(oid) != value:
                   raise ValueError(f"Unexpected subject attribute {key}: expected {value}, got {subject_dict.get(oid)}")

           return {"status": "success", "message": "Certificate is valid and usable"}

       except Exception as e:
           return {"status": "error", "message": str(e)}

if __name__ == "__main__":
       if len(sys.argv) != 4:
           print(json.dumps({"error": "Certificate hex, private key hex, and CA certificate path are required"}), file=sys.stdout)
           sys.exit(1)

       cert_hex = sys.argv[1]
       private_key_hex = sys.argv[2]
       ca_cert_path = sys.argv[3]

       result = verify_certificate(cert_hex, private_key_hex, ca_cert_path)
       print(json.dumps(result), file=sys.stdout)
       sys.exit(0 if result["status"] == "success" else 1)