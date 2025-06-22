const { exec } = require('child_process');
const util = require('util');
const crypto = require('crypto');
const { publish, subscribeToDeviceTopics } = require('./mqttClient');
const { createSpkiPublicKey, verifyCertificate } = require('./utils/certUtils');
const { storeDevice } = require('./utils/dbUtils');
const cryptoUtils = require('../crypto/chachapolyCryptoUtils/cryptoUtils');
const socketHandler = require('../websocket/socketHandler.js');

const execPromise = util.promisify(exec);
const sharedSecrets = new Map();

// Helper to generate expiry date (1 year from now)
function getOneYearExpiry() {
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);
  return expiryDate.toISOString();
}

async function handleDeviceKey(deviceId, data) {

  socketHandler.broadcastDeviceStatus(deviceId, {
    status: 'connecting',
    message: 'Đang xác minh chứng chỉ thiết bị'
  });

  console.log(`Entering handleDeviceKey for device ${deviceId}`);
  const { device_id, public_key_x, public_key_y, certificate } = data;

  if (device_id !== deviceId) {
    console.error(`Device ID mismatch: payload=${device_id}, topic=${deviceId}`);
    return;
  }

  console.log(`Handling device key for device ${deviceId}:`, {
    public_key_x,
    public_key_y,
    certificate_length: certificate ? certificate.length : 'N/A',
    certificate_snippet: certificate && certificate.length > 50 ? certificate.substring(0, 50) + '...' : certificate
  });

  if (!device_id || !public_key_x || !public_key_y || !certificate) {
    console.error(`Missing data for device ${deviceId}`);
    return;
  }

  const cleanCert = certificate.replace(/[^0-9a-fA-F]/g, '');
  if (cleanCert.length !== 1040) {
    console.error(`Certificate length incorrect for device ${deviceId}: expected 1040, got ${cleanCert.length}`);
    return;
  }

  console.log(`Verifying certificate for device ${deviceId}`);
  const cert = verifyCertificate(cleanCert);
  if (!cert) {
    console.error(`Invalid certificate for device ${deviceId}`);
    socketHandler.broadcastDeviceStatus(deviceId, {
      status: 'error',
      message: 'Chứng chỉ không hợp lệ'
    });
    return;
  }
  console.log(`Certificate verified successfully for device ${deviceId}`);

  socketHandler.broadcastDeviceStatus(deviceId, {
    status: 'connecting',
    message: 'chứng chỉ thiết bị hợp lệ'
  });

  try {
    const devicePubKey = createSpkiPublicKey(public_key_x, public_key_y);
    const certBytes = Buffer.from(cleanCert, 'hex');
    const certPem = `-----BEGIN CERTIFICATE-----\n${certBytes.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
    const certObj = new crypto.X509Certificate(certPem);

    if (devicePubKey.export({ type: 'spki', format: 'pem' }) !== certObj.publicKey.export({ type: 'spki', format: 'pem' })) {
      console.error(`Device public key does not match certificate public key for device ${deviceId}`);
      return;
    }
    console.log(`Public key matches certificate for device ${deviceId}`);

    socketHandler.broadcastDeviceStatus(deviceId, {
      status: 'connecting',
      message: 'Khóa công khai khớp với chứng chỉ'
    });

  } catch (err) {
    console.error(`Error verifying public key against certificate for device ${deviceId}:`, err.message);
    socketHandler.broadcastDeviceStatus(deviceId, {
      status: 'error',
      message: 'Khóa công khai không khớp với chứng chỉ'
    });
    return;
  }

//   console.log(`Generating certificate for device ${deviceId}`);
//   let certResponse;
//   try {
//     const { stdout, stderr } = await execPromise(`python generate_device_cert.py "${deviceId}"`);
//     if (stderr) {
//       console.error(`Python script error for device ${deviceId}:`, stderr);
//       return;
//     }
//     const result = JSON.parse(stdout);
//     if (result.error) {
//       console.error(`Certificate generation error for device ${deviceId}:`, result.error);
//       return;
//     }

//     // Override expiry to 1 year from now
//     const oneYearExpiry = getOneYearExpiry();
//     certResponse = {
//       device_id: result.device_id,
//       certificate: result.certificate,
//       private_key: result.private_key,
//       expiry: oneYearExpiry
//     };
//     const certTopic = `iot/${deviceId}/device_cert`;
//     publish(certTopic, JSON.stringify(certResponse), (err) => {
//       if (err) {
//         console.error(`Failed to publish certificate to ${certTopic}:`, err.message);
//       } else {
//         console.log(`Sent certificate to ${certTopic}:`, certResponse);
//       }
//     });
//   } catch (err) {
//     console.error(`Error generating certificate for device ${deviceId}:`, err.message);
//     return;
//   }

  console.log(`Computing shared secret for device ${deviceId}`);
  const result = cryptoUtils.computeSharedSecret(public_key_x, public_key_y);
  if (!result) {
    console.error(`Failed to compute shared secret for device ${deviceId}`);
    socketHandler.broadcastDeviceStatus(deviceId, {
      status: 'error',
      message: 'Không thể tạo khóa bí mật chung'
    });
    return;
  }

  sharedSecrets.set(deviceId, result.sharedSecret);
  console.log(`Stored shared secret for device ${deviceId}`);

  socketHandler.broadcastDeviceStatus(deviceId, {
      status: 'connecting',
      message: 'Tạo khóa bí mật chung'
  });

  console.log(`Storing device ${deviceId} in database`);
//   try {
//     // Store device metadata
//     await storeDevice({
//       device_id,
//       public_key_x,
//       public_key_y,
//       shared_secret: result.sharedSecret.toString('hex')
//     });

//     // Store or update certificate
//     const existingCert = await DeviceCert.findOne({ device_id });
//     const certData = {
//       device_id,
//       certificate: cleanCert,
//       expiry: certResponse.expiry,
//       status: certResponse.expiry <= new Date().toISOString() ? 'expired' : 'active'
//     };
//     if (existingCert) {
//       await DeviceCert.findOneAndUpdate({ device_id }, certData);
//       console.log(`Updated certificate for device ${deviceId} in database`);
//     } else {
//       await DeviceCert.create(certData);
//       console.log(`Created new certificate for device ${deviceId} in database`);
//     }

//     subscribeToDeviceTopics([deviceId]);
//   } catch (err) {
//     console.error(`Failed to store device or certificate for device ${deviceId}:`, err.message);
//     return;
//   }

  const serverKey = {
    public_key_x: result.serverPubKeyX,
    public_key_y: result.serverPubKeyY
  };
  const serverKeyTopic = `iot/${deviceId}/server_key`;
  publish(serverKeyTopic, JSON.stringify(serverKey), (err) => {
    if (err) {
      console.error(`Failed to publish server key to ${serverKeyTopic}:`, err.message);
    } else {
      console.log(`Sent server public key to ${serverKeyTopic}:`, serverKey);
    }
  });

  socketHandler.broadcastDeviceStatus(deviceId, {
    status: 'success',
    message: 'Thiết bị đã xác thực thành công',
    details: {
      publicKey: { x: data.public_key_x, y: data.public_key_y },
      certificate: {
        subject: cert.subject,
        expires: cert.validTo
      }
    }
  });
}

module.exports = { handleDeviceKey, sharedSecrets };