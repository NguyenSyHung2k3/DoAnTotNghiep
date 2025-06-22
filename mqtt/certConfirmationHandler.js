const crypto = require('crypto');
const CertConfirmation = require('../models/CertConfirmation.js');

async function handleCertConfirmation(deviceId, data) {
  console.log(`Entering handleCertConfirmation for device ${deviceId}`);
  const { device_id, status, certificate_hash, timestamp, message } = data;

  if (device_id !== deviceId) {
    console.error(`Device ID mismatch: payload=${device_id}, topic=${deviceId}`);
    return;
  }

  if (!device_id || !status || !certificate_hash || !timestamp) {
    console.error(`Missing data in cert confirmation for device ${deviceId}`);
    return;
  }

  try {
    const confirmation = new CertConfirmation({
      device_id,
      status,
      certificate_hash,
      message: status === 'error' ? message : undefined,
      timestamp: new Date(timestamp)
    });
    await confirmation.save();
    console.log(`Stored certificate confirmation for device ${deviceId}: status=${status}, hash=${certificate_hash}`);
  } catch (err) {
    console.error(`Failed to store certificate confirmation for device ${deviceId}:`, err.message);
  }
}

module.exports = { handleCertConfirmation };