import subprocess
import json
import sys
import tempfile
import os

def verify_signature(data, signature_hex, cert_hex):
           try:
               with tempfile.TemporaryDirectory() as temp_dir:
                   cert_file = os.path.join(temp_dir, "device.crt")
                   data_file = os.path.join(temp_dir, "data.txt")
                   sig_file = os.path.join(temp_dir, "signature.bin")

                   # Ghi chứng thư
                   cert_der = bytes.fromhex(cert_hex)
                   with open(cert_file, "wb") as f:
                       f.write(cert_der)

                   # Ghi dữ liệu
                   with open(data_file, "w") as f:
                       f.write(data)

                   # Ghi chữ ký
                   signature = bytes.fromhex(signature_hex)
                   with open(sig_file, "wb") as f:
                       f.write(signature)

                   # Xác minh chữ ký
                   result = subprocess.run([
                       "openssl", "dgst", "-sha256", "-verify", cert_file,
                       "-signature", sig_file, data_file
                   ], capture_output=True, text=True, check=False)

                   if result.returncode != 0:
                       raise ValueError(f"Xác minh chữ ký thất bại: {result.stderr}")

                   return {"status": "success", "message": "Chữ ký đã được xác minh"}

           except subprocess.CalledProcessError as e:
               return {"status": "error", "message": f"Lệnh OpenSSL thất bại: {e.stderr}"}
           except Exception as e:
               return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(json.dumps({"error": "Yêu cầu dữ liệu, hex chữ ký và hex chứng thư"}))
        sys.exit(1)

    data = sys.argv[1]
    signature_hex = sys.argv[2]
    cert_hex = sys.argv[3]

    result = verify_signature(data, signature_hex, cert_hex)
    print(json.dumps(result))
    sys.exit(0 if result["status"] == "success" else 1)