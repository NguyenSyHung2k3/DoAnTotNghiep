const express = require('express');
const { 
  saveEncryptedData,
  getAllEncryptedData, 
  getEncryptedDataByDeviceId,
  getDecryptionStats 
} = require('../controllers/encryptedSensorController');

const router = express.Router();

// Lưu dữ liệu đã mã hóa mới
router.post('/encrypted', saveEncryptedData);

// Lấy tất cả dữ liệu đã mã hóa
router.get('/encrypted', getAllEncryptedData);

// Lấy dữ liệu đã mã hóa theo device_id
router.get('/encrypted/:device_id', getEncryptedDataByDeviceId);

// Lấy thống kê về trạng thái giải mã
router.get('/encrypted/stats/decryption', getDecryptionStats);

module.exports = router; 