const express = require('express');
const subscriberController = require('../controllers/subscriberController');

const router = express.Router();

router.post('/subscribe', subscriberController.subscribeDevice);
router.post('/unsubscribe', subscriberController.unsubscribeDevice);
router.get('/devices', subscriberController.getSubscribedDevices);

module.exports = router;