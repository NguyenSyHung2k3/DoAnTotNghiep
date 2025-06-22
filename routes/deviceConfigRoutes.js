const express = require('express');
const { sendDeviceConfig } = require('../controllers/deviceConfigController');

const router = express.Router();
router.post('/:device_id/:device_id_recv', sendDeviceConfig);

module.exports = router; 