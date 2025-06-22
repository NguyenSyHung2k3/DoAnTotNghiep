require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const mqttConfig = {
  host: process.env.MQTT_HOST,
  port: process.env.MQTT_PORT,
  protocol: 'mqtts',
  username: process.env.MQTT_USERNAME,
  password: process.env.MQTT_PASSWORD,
  rejectUnauthorized: false,
  maxPacketSize: 8192 // Increased to handle large certificates
};

const mongoConfig = {
  uri: process.env.MONGODB_URI
};

const caCertPath = path.join(__dirname, '../certs/certs/ca-cert.pem');
let caCertPem;
try {
  caCertPem = fs.readFileSync(caCertPath, 'utf8');
  console.log('CA certificate loaded successfully from:', caCertPath);

  // Kiểm tra khóa công khai CA
  const caCert = new crypto.X509Certificate(caCertPem);
  console.log('CA certificate public key verified successfully');
} catch (err) {
  console.error('Failed to read or verify CA certificate from file:', err.message);
  throw new Error(`Unable to load or verify CA certificate: ${err.message}`);
}

const caPrivateKeyPath = path.join(__dirname, '../certs/certs/ca-key.pem');
let caPrivateKeyPem;
try {
  caPrivateKeyPem = fs.readFileSync(caPrivateKeyPath, 'utf8');
  console.log('CA private key loaded successfully from:', caPrivateKeyPath);
} catch (err) {
  console.error('Failed to read CA private key from file:', err.message);
  throw new Error(`Unable to load CA private key: ${err.message}`);
}

function getDecryptedPrivateKey() {
  const encryptedKeyPath = path.join(__dirname, '../certs/certDevice/ca-key.encrypted.pem');
  const passphrase = process.env.CA_KEY_PASSPHRASE;
  
  if (!passphrase) {
    throw new Error('CA_KEY_PASSPHRASE is missing in .env');
  }

  try {
    // Gọi Python script để giải mã
    const result = spawnSync('python', [
      path.join(__dirname, '../certs/certDevice/decrypt_key.py'),
      encryptedKeyPath,
      passphrase
    ]);

    if (result.error) {
      throw result.error;
    }

    if (result.status !== 0) {
      throw new Error(result.stderr.toString());
    }

    return result.stdout.toString('utf8').trim();
  } catch (err) {
    console.error('Failed to decrypt CA private key:', err.message);
    throw new Error(`Unable to decrypt CA private key: ${err.message}`);
  }
}

module.exports = {
  mqttConfig,
  mongoConfig,
  caCertPem,
  caPrivateKeyPem,
  caPrivateKeyPemPath: 'C:\\Users\\pv\\OneDrive\\Desktop\\DATN\\datn\\src\\certs\\certs\\ca-key.pem',
  caCertPemPath: 'C:\\Users\\pv\\OneDrive\\Desktop\\DATN\\datn\\src\\certs\\certs\\ca-cert.pem',
  getDecryptedPrivateKey,
};