const { exec } = require('child_process');
const util = require('util');
const { publish } = require('./mqttClient');

const execPromise = util.promisify(exec);

function isCertificateExpired(expiry) {
  try {
    const expiryDate = new Date(expiry);
    const now = new Date();
    return now >= expiryDate;
  } catch (err) {
    console.error('Error parsing expiry date:', err.message);
    return false;
  }
}

// Helper to generate expiry date (1 year from now)
function getOneYearExpiry() {
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);
  return expiryDate.toISOString();
}

async function handleCertificateRenewal(deviceId, data) {
  console.log(`Entering handleCertificateRenewal for device ${deviceId}`);
  const { device_id, request } = data;

  if (device_id !== deviceId) {
    console.error(`Device ID mismatch: payload=${device_id}, topic=${deviceId}`);
    return;
  }

  if (request !== 'renew_certificate') {
    console.error(`Invalid renewal request for device ${deviceId}`);
    return;
  }

  console.log(`Generating new certificate for device ${deviceId}`);
  try {
    const { stdout, stderr } = await execPromise(`python generate_device_cert.py "${deviceId}"`);
    if (stderr) {
      console.error(`Python script error for device ${deviceId}:`, stderr);
      return;
    }
    const result = JSON.parse(stdout);
    if (result.error) {
      console.error(`Certificate generation error for device ${deviceId}:`, result.error);
      return;
    }

    const oneYearExpiry = getOneYearExpiry();
    const certResponse = {
      device_id: result.device_id,
      certificate: result.certificate,
      private_key: result.private_key,
      expiry: oneYearExpiry
    };
    const certTopic = `iot/${deviceId}/device_cert`;
    publish(certTopic, JSON.stringify(certResponse), (err) => {
      if (err) {
        console.error(`Failed to publish new certificate to ${certTopic}:`, err.message);
      } else {
        console.log(`Sent new certificate to ${certTopic}:`, certResponse);
      }
    });

    const status = isCertificateExpired(oneYearExpiry) ? 'expired' : 'active';
    await DeviceCert.findOneAndUpdate(
      { device_id: deviceId },
      {
        certificate: result.certificate,
        expiry: oneYearExpiry,
        status
      },
      { upsert: true }
    );
    console.log(`Updated device ${deviceId} with new certificate in database, status: ${status}`);
  } catch (err) {
    console.error(`Error generating new certificate for device ${deviceId}:`, err.message);
  }
}

module.exports = { handleCertificateRenewal };