const express = require('express');
const { getDeviceCertificate, renewCertificate, revokeCertificate, getCRL } = require('../controllers/certController');
const router = express.Router();

router.post('/renew/:deviceId', renewCertificate);
router.get('/:deviceId', getDeviceCertificate);
router.post('/revoke/:deviceId', revokeCertificate);
router.get('/crl/abc', getCRL);

module.exports = router;