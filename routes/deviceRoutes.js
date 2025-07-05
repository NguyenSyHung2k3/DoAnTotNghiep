const express = require('express');
const {
  registerDevice,
  deleteDevice,
  getDevice,
  getDevicesAll
} = require('../controllers/deviceController');

const router = express.Router();

router.post('/register', registerDevice);
router.delete('/:device_id', deleteDevice);
router.get('/:device_id', getDevice);
router.get('/all/devices', getDevicesAll);

module.exports = router; 