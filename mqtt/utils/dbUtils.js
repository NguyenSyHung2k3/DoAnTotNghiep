const Device = require('../../models/Device');

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

async function storeDevice(deviceData) {
  const { device_id, public_key_x, public_key_y, shared_secret } = deviceData;
  try {
    const device = await Device.findOneAndUpdate(
      { device_id },
      {
        device_id,
        public_key_x,
        public_key_y,
        shared_secret
      },
      { upsert: true, new: true }
    );
    console.log(`Stored device ${device_id} in database`);
    return device;
  } catch (err) {
    throw new Error(`Failed to store device ${device_id} in database: ${err.message}`);
  }
}

// async function updateDeviceStatuses() {
//   try {
//     const certs = await DeviceCert.find({}, 'device_id expiry status');
//     for (const cert of certs) {
//       if (isCertificateExpired(cert.expiry) && cert.status !== 'expired') {
//         await DeviceCert.findOneAndUpdate(
//           { device_id: cert.device_id },
//           { status: 'expired' }
//         );
//         console.log(`Updated status to 'expired' for device ${cert.device_id}`);
//       }
//     }
//   } catch (err) {
//     console.error('Error updating device certificate statuses:', err.message);
//   }
// }

module.exports = { storeDevice };