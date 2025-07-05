import json
import sys
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtensionOID

def revoke_device_cert(device_id, ca_cert_path="ca-cert.pem", ca_key_path="ca-key.pem", serial=None, crl_path="ca_data/crl.pem"):
    try:
        if not os.path.exists(ca_cert_path):
            return {"status": "error", "message": f"Tệp chứng thư CA không tồn tại: {ca_cert_path}"}
        if not os.path.exists(ca_key_path):
            return {"status": "error", "message": f"Tệp khóa CA không tồn tại: {ca_key_path}"}
        if not serial:
            return {"status": "error", "message": "Số serial của chứng thư là bắt buộc"}

        ca_data_dir = "ca_data"
        if not os.path.exists(ca_data_dir):
            os.makedirs(ca_data_dir)

        index_file = os.path.join(ca_data_dir, "index.txt")
        serial_file = os.path.join(ca_data_dir, "serial")
        config_file = os.path.join(ca_data_dir, "openssl.cnf")

        if not os.path.exists(index_file):
            open(index_file, "a").close()

        if not os.path.exists(serial_file):
            with open(serial_file, "w") as f:
                f.write("1000\n")

        # Tạo tệp cấu hình OpenSSL nếu chưa có
        if not os.path.exists(config_file):
            with open(config_file, "w") as f:
                f.write("""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {ca_data_dir}
database = {index_file}
serial = {serial_file}
default_days = 365
default_crl_days = 30
default_md = sha256
""".format(ca_data_dir=ca_data_dir, index_file=index_file, serial_file=serial_file))

        # Load chứng thư CA
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load khóa riêng CA
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        # Đọc index.txt để kiểm tra chứng thư
        revoked_certs = []
        try:
            with open(index_file, "r") as f:
                for line in f:
                    fields = line.strip().split("\t")
                    if len(fields) >= 6 and fields[3] == serial:
                        revoked_certs.append({
                            "serial": fields[3],
                            "revocation_date": datetime.utcnow(),
                            "reason": None
                        })
        except Exception as e:
            return {"status": "error", "message": f"Lỗi khi đọc tệp index.txt: {str(e)}"}

        # Nếu chứng thư chưa được đánh dấu là thu hồi, thêm vào index.txt
        if not revoked_certs:
            with open(index_file, "a") as f:
                revocation_time = datetime.utcnow().strftime("%y%m%d%H%M%SZ")
                f.write(f"R\t{revocation_time}\t\t{serial}\tunknown\t/C=VN/ST=Hanoi/L=Giangvo/O=MyIoT/OU=IoT/CN=ESP32_Sensor\n")

        # Tạo CRL
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(datetime.utcnow() + timedelta(days=30))

        # Thêm chứng thư bị thu hồi vào CRL
        for cert_info in revoked_certs:
            revoked_cert = x509.RevokedCertificateBuilder()
            revoked_cert = revoked_cert.serial_number(int(cert_info["serial"], 16))
            revoked_cert = revoked_cert.revocation_date(cert_info["revocation_date"])
            if cert_info["reason"]:
                revoked_cert = revoked_cert.add_extension(
                    x509.CRLReason(x509.ReasonFlags[cert_info["reason"]]),
                    critical=False
                )
            builder = builder.add_revoked_certificate(revoked_cert.build())

        # Ký CRL
        crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

        # Lưu CRL vào tệp
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        # Chuyển CRL sang định dạng DER và hex
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        crl_hex = crl_der.hex()

        # Tính thời gian hết hạn của CRL
        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat()

        return {
            "status": "success",
            "device_id": device_id,
            "crl_hex": crl_hex,
            "expiry": expiry
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(json.dumps({"error": "Yêu cầu Device ID, đường dẫn chứng thư CA, khóa CA và số serial"}))
        sys.exit(1)

    device_id = sys.argv[1]
    ca_cert_path = sys.argv[2]
    ca_key_path = sys.argv[3]
    serial = sys.argv[4]

    try:
        result = revoke_device_cert(device_id, ca_cert_path, ca_key_path, serial)
        print(json.dumps(result))
        sys.exit(0 if result["status"] == "success" else 1)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)