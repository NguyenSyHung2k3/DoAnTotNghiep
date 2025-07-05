const express = require('express');
const { getAllSensors, getSensorsByDeviceId, getEncryptionStats } = require('../controllers/sensorController');
const router = express.Router();

router.get('/sensors', getAllSensors);
router.get('/sensors/:device_id', getSensorsByDeviceId);
router.get('/sensors/stats/encryption', getEncryptionStats);

module.exports = router;