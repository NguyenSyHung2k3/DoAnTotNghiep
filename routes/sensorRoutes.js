const express = require('express');
const { getAllSensors, getSensorsByDeviceId, getEncryptionStats } = require('../controllers/sensorController');
const router = express.Router();

// Lấy tất cả dữ liệu cảm biến
router.get('/sensors', getAllSensors);

// Lấy dữ liệu cảm biến theo device_id
router.get('/sensors/:device_id', getSensorsByDeviceId);

// Lấy thống kê về loại mã hóa
router.get('/sensors/stats/encryption', getEncryptionStats);

module.exports = router;