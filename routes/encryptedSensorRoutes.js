const express = require('express');
const { 
  saveEncryptedData,
  getAllEncryptedData, 
  getEncryptedDataByDeviceId,
  getDecryptionStats 
} = require('../controllers/encryptedSensorController');

const router = express.Router();

router.post('/encrypted', saveEncryptedData);
router.get('/encrypted', getAllEncryptedData);
router.get('/encrypted/:device_id', getEncryptedDataByDeviceId);
router.get('/encrypted/stats/decryption', getDecryptionStats);

module.exports = router; 