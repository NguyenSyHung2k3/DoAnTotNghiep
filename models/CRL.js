const mongoose = require('mongoose');
const { Schema } = mongoose;
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

const RevokedCertificateSchema = new Schema({
  deviceId: {
    type: String,
    required: true,
    index: true
  },
  serialNumber: {
    type: String,
    required: true,
    unique: true
  },
  revocationDate: {
    type: Date,
    required: true,
    default: Date.now
  },
  reason: {
    type: String,
    enum: [
      'unspecified',
      'keyCompromise',
      'cACompromise',
      'affiliationChanged',
      'superseded',
      'cessationOfOperation',
      'certificateHold',
      'removeFromCRL',
      'privilegeWithdrawn',
      'aACompromise'
    ],
    default: 'unspecified'
  },
  issuer: {
    type: String,
    required: true
  }
}, { _id: false });

const CRLSchema = new Schema({
  issuer: {
    type: String,
    required: true,
    unique: true
  },
  thisUpdate: {
    type: Date,
    required: true,
    default: Date.now
  },
  nextUpdate: {
    type: Date,
    required: true
  },
  revokedCertificates: [RevokedCertificateSchema],
  crlNumber: {
    type: Number,
    required: true,
    default: 1
  },
  crlPem: {
    type: String,
    required: true
  }
});

CRLSchema.methods.updateCRL = async function(newRevokedCerts, caPrivateKeyPem) {
  const scriptPath = path.join(__dirname, '../certs/certDevice/revoke_device_cert.py');
  const caCertPath = path.join(__dirname, '../certs/certDevice/ca-cert.pem');
  const caKeyPath = path.join(__dirname, '../certs/certDevice/ca-key.pem');
  const crlPath = path.join(__dirname, '../certs/certDevice/ca_data/crl.pem');

  // Tạo thư mục nếu chưa tồn tại
  const caDataDir = path.dirname(crlPath);
  if (!fs.existsSync(caDataDir)) {
    fs.mkdirSync(caDataDir, { recursive: true });
  }

  try {
    // Thực thi Python script bằng spawn
    for (const cert of newRevokedCerts) {
      const pythonProcess = spawn('python', [
        scriptPath,
        cert.deviceId,
        caCertPath,
        caKeyPath,
        cert.serialNumber
      ]);

      // Xử lý kết quả trả về từ Python script
      const result = await new Promise((resolve, reject) => {
        let stdout = '';
        let stderr = '';

        pythonProcess.stdout.on('data', (data) => {
          stdout += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
          stderr += data.toString();
        });

        pythonProcess.on('close', (code) => {
          if (code !== 0) {
            reject(new Error(`Python script exited with code ${code}: ${stderr}`));
          } else {
            try {
              resolve(JSON.parse(stdout));
            } catch (e) {
              reject(new Error(`Failed to parse Python script output: ${e.message}`));
            }
          }
        });

        pythonProcess.on('error', (err) => {
          reject(new Error(`Failed to start Python process: ${err.message}`));
        });
      });

      if (result.status !== 'success') {
        throw new Error(result.message || 'Failed to revoke certificate');
      }

      this.revokedCertificates.push({
        deviceId: cert.deviceId,
        serialNumber: cert.serialNumber,
        revocationDate: cert.revocationDate || new Date(),
        reason: cert.reason || 'unspecified',
        issuer: this.issuer,
      })

    }

    // Đọc và cập nhật CRL
    this.crlPem = fs.readFileSync(crlPath, 'utf8');
    this.crlNumber += 1;
    this.thisUpdate = new Date();
    this.nextUpdate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    return this.save();
  } catch (error) {
    console.error('Error in updateCRL:', error);
    throw new Error(`CRL update failed: ${error.message}`);
  }
};

CRLSchema.statics.isCertificateRevoked = async function(serialNumber, issuer) {
  const crl = await this.findOne({ 
    issuer,
    'revokedCertificates.serialNumber': serialNumber 
  });
  return !!crl;
};

const CRL = mongoose.model('CRL', CRLSchema);

module.exports = CRL;