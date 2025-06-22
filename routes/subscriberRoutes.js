const express = require('express');
const subscriberController = require('../controllers/subscriberController');

const router = express.Router();

// Subscribe to a device
router.post('/subscribe', subscriberController.subscribeDevice);

// Unsubscribe from a device
router.post('/unsubscribe', subscriberController.unsubscribeDevice);

// Get list of subscribed devices
router.get('/devices', subscriberController.getSubscribedDevices);

module.exports = router;