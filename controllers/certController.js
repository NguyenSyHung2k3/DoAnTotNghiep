const { renewCertificate: renewCertificateService, revokeCertificate: revokeCertificateService } = require('../services/certService');
const { publish, onMessage } = require('../mqtt/mqttClient');
const Device = require('../models/Device');
const CRL = require('../models/CRL');
const fs = require('fs');
const path = require('path');

const pendingCertificates = new Map();

const getDeviceCertificate = async (req, res) => {
    try {
        const { deviceId } = req.params;
        
        const device = await Device.findOne({ device_id: deviceId });
        
        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'Device not found'
            });
        }

        return res.status(200).json({
            success: true,
            data: {
                device_id: device.device_id,
                serial_number: device.serial,
                certificate: device.certificate,
                public_key_x: device.public_key_x,
                public_key_y: device.public_key_y,
                shared_secret: device.shared_secret,
                expiry: device.expiry,
                status: device.status,
                registered_at: device.registered_at
            }
        });
    } catch (error) {
        console.error('Error getting device certificate:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

const renewCertificate = async (req, res) => {
    try {
        const { deviceId } = req.params;
        
        // Check if device exists
        const device = await Device.findOne({ device_id: deviceId });
        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'Device not found'
            });
        }

        // Generate new certificate
        const newCert = await renewCertificateService(deviceId);
        if (!newCert) {
            return res.status(500).json({
                success: false,
                message: 'Failed to generate new certificate'
            });
        }

        // Update device with new certificate
        await Device.findOneAndUpdate(
            { device_id: deviceId },
            {
                certificate: newCert.certificate,
                certificate_expiry: newCert.expiry,
                certificate_status: 'active'
            }
        );

        // Publish new certificate to device via MQTT
        const certTopic = `iot/${deviceId}/device_cert`;
        const certResponse = {
            device_id: deviceId,
            certificate: newCert.certificate,
            private_key: newCert.private_key,
            expiry: newCert.expiry
        };

        publish(certTopic, JSON.stringify(certResponse), (err) => {
            if (err) {
                console.error(`Failed to publish new certificate to ${certTopic}:`, err.message);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to send certificate to device'
                });
            }
        });

        return res.status(200).json({
            success: true,
            message: 'Certificate renewed successfully',
            data: {
                device_id: deviceId,
                expiry: newCert.expiry
            }
        });
    } catch (error) {
        console.error('Error renewing certificate:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

const revokeCertificate = async (req, res) => {
    try {
        const { deviceId } = req.params;
        const { serial } = req.body;

        const device = await Device.findOne({device_id: deviceId, serial: serial});
        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'Device or serial not found'
            });
        }
        if (device.status === 'revoked') {
            return res.status(400).json({
                success: false,
                message: 'Device certificate already revoked'
            });
        }

        // Revoke certificate
        const revokeResult = await revokeCertificateService(deviceId, serial);
        if (!revokeResult) {
            return res.status(500).json({
                success: false,
                message: 'Failed to revoke certificate'
            });
        }

        return res.status(200).json({
            success: true,
            message: `Certificate for device ${deviceId} revoked`,
            data: {
                device_id: deviceId,
                crl_hex: revokeResult.crl_hex,
                expiry: revokeResult.expiry,
                crl_pem: revokeResult.crl_pem
            }
        });
    } catch (error) {
        console.error('Error revoking certificate:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}

const getCRL = async (req, res) => {
    try {
        const caCertPath = path.resolve(process.env.CA_CERT_PATH);
        
        let caCertPem;
        try {
            caCertPem = fs.readFileSync(caCertPath, 'utf8');
        } catch (err) {
            return res.status(400).json({
                success: false,
                message: 'Không thể đọc file CA certificate'
            });
        }

        // Tìm CRL tương ứng với issuer (CA certificate)
        const crl = await CRL.findOne({ issuer: caCertPem })
            .sort({ thisUpdate: -1 }) // Lấy bản CRL mới nhất
            .exec();

        if (!crl) {
            return res.status(404).json({
                success: false,
                message: 'Không tìm thấy CRL cho CA này'
            });
        }

        return res.status(200).json({
            success: true,
            data: {
                issuer: crl.issuer,
                thisUpdate: crl.thisUpdate,
                nextUpdate: crl.nextUpdate,
                crlNumber: crl.crlNumber,
                revokedCertificates: crl.revokedCertificates,
                crlPem: crl.crlPem
            }
        });
    } catch (error) {
        console.error('Lỗi khi lấy CRL:', error);
        return res.status(500).json({
            success: false,
            message: 'Lỗi server khi xử lý yêu cầu CRL'
        });
    }
}

module.exports = { getDeviceCertificate, renewCertificate, revokeCertificate, getCRL };