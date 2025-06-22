const { spawn } = require('child_process');
const { publish, onMessage } = require('../mqtt/mqttClient');
const Device = require('../models/Device');
const CRL = require('../models/CRL');
const CertConfirmation = require('../models/CertConfirmation');
const path = require('path');
const fs = require('fs');

const MAX_RETRIES = 3;
const RETRY_DELAY = 5000; // 5 seconds

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const renewCertificate = async (deviceId, retryCount = 0) => {
    try {
        // Find device in database
        const device = await Device.findOne({ device_id: deviceId });
        if (!device) {
            throw new Error(`Device ${deviceId} not found in database`);
        }

        // Paths to Python scripts and CA files
        const certScriptPath = path.join(__dirname, '../certs/certDevice/generate_device_cert.py');
        const verifyScriptPath = path.join(__dirname, '../certs/certDevice/verify_device_cert.py');
        const caCertPath = path.join(__dirname, '../certs/certDevice/ca-cert.pem');
        const caKeyPath = path.join(__dirname, '../certs/certDevice/ca-key.pem');

        // Execute certificate generation script
        const certDir = path.join(__dirname, '../certs/certDevice');
        const certProcess = spawn('python', [
            certScriptPath,
            deviceId,
            caCertPath,
            caKeyPath
        ], { cwd: certDir });

        let certStdout = '';
        let certStderr = '';

        certProcess.stdout.on('data', (data) => {
            certStdout += data.toString();
        });

        certProcess.stderr.on('data', (data) => {
            certStderr += data.toString();
        });

        const certExitCode = await new Promise((resolve) => {
            certProcess.on('close', (code) => resolve(code));
        });

        if (certExitCode !== 0) {
            console.error(`Certificate generation error for device ${deviceId}:`, certStderr);
            throw new Error('Failed to generate certificate');
        }

        const certResult = JSON.parse(certStdout);
        if (certResult.error) {
            console.error(`Certificate generation error for device ${deviceId}:`, certResult.error);
            throw new Error(`Failed to generate certificate: ${certResult.error}`);
        }

        // Verify the generated certificate
        const verifyProcess = spawn('python', [
            verifyScriptPath,
            certResult.certificate,
            certResult.private_key,
            caCertPath
        ], { cwd: certDir });

        let verifyStdout = '';
        let verifyStderr = '';

        verifyProcess.stdout.on('data', (data) => {
            verifyStdout += data.toString();
        });

        verifyProcess.stderr.on('data', (data) => {
            verifyStderr += data.toString();
        });

        const verifyExitCode = await new Promise((resolve) => {
            verifyProcess.on('close', (code) => resolve(code));
        });

        if (verifyExitCode !== 0) {
            console.error(`Certificate verification error for device ${deviceId}:`, verifyStderr);
            throw new Error('Certificate verification failed');
        }

        const verifyResult = JSON.parse(verifyStdout);
        if (verifyResult.status !== 'success') {
            console.error(`Certificate verification failed for device ${deviceId}:`, verifyResult.message);
            throw new Error(`Certificate verification failed: ${verifyResult.message}`);
        }
        console.log(`Certificate verified successfully for device ${deviceId}`);

        // Wait for certificate confirmation from device
        const certTopic = `iot/${deviceId}/device_cert`;
        const confirmTopic = `iot/${deviceId}/cert_confirmation`;
        const certResponse = {
            device_id: deviceId,
            certificate: certResult.certificate,
            private_key: certResult.private_key,
            serial: certResult.serial,
            expiry: certResult.expiry
        };

        // Set up promise to wait for confirmation
        const confirmationTimeout = 30000; // 30 seconds timeout
        const confirmationPromise = new Promise((resolve, reject) => {
            const handler = (topic, message) => {
                if (topic === confirmTopic) {
                    try {
                        const confirmation = JSON.parse(message.toString());
                        if (confirmation.device_id === deviceId) {
                            // Unregister handler to prevent memory leaks
                            messageHandlers.splice(messageHandlers.indexOf(handler), 1);
                            resolve(confirmation);
                        }
                    } catch (err) {
                        console.error(`Error parsing confirmation for ${deviceId}:`, err.message);
                    }
                }
            };

            // Register message handler
            const messageHandlers = [];
            onMessage(handler);
            messageHandlers.push(handler);

            // Set timeout
            setTimeout(() => {
                messageHandlers.splice(messageHandlers.indexOf(handler), 1);
                reject(new Error(`Timeout waiting for certificate confirmation from ${deviceId}`));
            }, confirmationTimeout);
        });

        // Publish new certificate to device
        await new Promise((resolve, reject) => {
            publish(certTopic, JSON.stringify(certResponse), { qos: 1 }, (err) => {
                if (err) {
                    console.error(`Failed to publish new certificate to ${certTopic}:`, err.message);
                    reject(new Error('Failed to send certificate to device'));
                } else {
                    console.log(`Sent new certificate to ${certTopic}:`, certResponse);
                    resolve();
                }
            });
        });

        try {
            // Wait for and process confirmation
            const confirmation = await confirmationPromise;
            if (confirmation.status !== 'success') {
                throw new Error(`Certificate installation failed on device ${deviceId}: ${confirmation.message || 'Unknown error'}`);
            }

            // Save confirmation to database
            const certConfirmation = new CertConfirmation({
                device_id: confirmation.device_id,
                status: confirmation.status,
                certificate_hash: confirmation.certificate_hash,
                message: confirmation.message || '',
                timestamp: new Date(confirmation.timestamp)
            });
            await certConfirmation.save();
            console.log(`Saved certificate confirmation for ${deviceId} to database`);

            // Update device with new certificate info
            await Device.findOneAndUpdate(
                { device_id: deviceId },
                {
                    serial: certResult.serial,
                    certificate: certResult.certificate,
                    expiry: certResult.expiry,
                    status: 'active'
                }
            );
            console.log(`Updated Device collection for ${deviceId} with new certificate`);

            return {
                certificate: certResult.certificate,
                private_key: certResult.private_key,
                expiry: certResult.expiry
            };
        } catch (error) {
            if (error.message.includes('Timeout') && retryCount < MAX_RETRIES) {
                console.log(`Retrying certificate renewal for device ${deviceId} (attempt ${retryCount + 1}/${MAX_RETRIES})`);
                await sleep(RETRY_DELAY);
                return renewCertificate(deviceId, retryCount + 1);
            }
            throw error;
        }
    } catch (err) {
        console.error('Error in renewCertificate service:', err.message);
        if (err.message.includes('Timeout') && retryCount < MAX_RETRIES) {
            console.log(`Retrying certificate renewal for device ${deviceId} (attempt ${retryCount + 1}/${MAX_RETRIES})`);
            await sleep(RETRY_DELAY);
            return renewCertificate(deviceId, retryCount + 1);
        }
        throw err;
    }
};

const verifySensorData = async (deviceId, data, signatureHex) => {
    try {
        const device = await Device.findOne({device_id: deviceId});
        if(!device) {
            throw new Error(`Khong tim thay thiet bi ${deviceId}`);
        }

        const verifyProcess = spawn('python', [
            path.join(__dirname, '../certs/certDevice/verify_signature.py'),
            data,
            signatureHex,
            device.certificate
        ], { cwd: certDir });

        let verifyStdout = '';
        let verifyStderr = '';

        verifyProcess.stdout.on('data', (data) => {
            verifyStdout += data.toString();
        });

        verifyProcess.stderr.on('data', (data) => {
            verifyStderr += data.toString();
        });

        const verifyExitCode = await new Promise((resolve) => {
            verifyProcess.on('close', (code) => resolve(code));
        });

        if (verifyExitCode !== 0) {
            console.error(`Lỗi xác minh chữ ký cho thiết bị ${deviceId}:`, verifyStderr);
            throw new Error('Không thể xác minh chữ ký');
        }

        const verifyResult = JSON.parse(verifyStdout);
        if (verifyResult.status !== 'success') {
            throw new Error(`Xác minh chữ ký thất bại: ${verifyResult.message}`);
        }

        return { status: 'success', message: 'Chữ ký đã được xác minh' };
    } catch (err) {
        console.error('Lỗi trong verifySensorData:', err.message);
        throw err;
    }
}

const revokeCertificate = async (deviceId, serial) => {
    try {
        const device = await Device.findOne({ device_id: deviceId, serial });
        if (!device) {
            throw new Error(`Device ${deviceId} with serial ${serial} not found`);
        }
        if (device.status === 'revoked') {
            throw new Error(`Device ${deviceId} is already revoked`);
        }

        const revokeScriptPath = path.join(__dirname, '../certs/certDevice/revoke_device_cert.py');
        const caCertPath = path.join(__dirname, '../certs/certDevice/ca-cert.pem');
        const caKeyPath = path.join(__dirname, '../certs/certDevice/ca-key.pem');
        const crlPath = path.join(__dirname, '../certs/certDevice/ca_data/crl.pem');

        // Đọc CA certificate để lấy issuer
        const caCertPem = fs.readFileSync(caCertPath, 'utf8');

        const certDir = path.join(__dirname, '../certs/certDevice');
        const revokeProcess = spawn('python', [
            revokeScriptPath,
            deviceId,
            caCertPath,
            caKeyPath,
            serial
        ], { cwd: certDir });

        let revokeStdout = '';
        let revokeStderr = '';

        revokeProcess.stdout.on('data', (data) => {
            revokeStdout += data.toString();
        });

        revokeProcess.stderr.on('data', (data) => {
            revokeStderr += data.toString();
        });

        const revokeExitCode = await new Promise((resolve) => {
            revokeProcess.on('close', (code) => resolve(code));
        });

        if (revokeExitCode !== 0) {
            console.error(`Certificate revocation error for device ${deviceId}:`, revokeStderr);
            throw new Error('Failed to revoke certificate');
        }

        const revokeResult = JSON.parse(revokeStdout);
        if (revokeResult.status !== 'success') {
            console.error(`Certificate revocation error for device ${deviceId}:`, revokeResult.message);
            throw new Error(`Failed to revoke certificate: ${revokeResult.message}`);
        }

        // Đọc CRL từ file
        const crlPem = fs.readFileSync(crlPath, 'utf8');

        // Tìm hoặc tạo CRL trong database
        let crl = await CRL.findOne({ issuer: caCertPem });
        
        if (!crl) {
            crl = new CRL({
                issuer: caCertPem,
                thisUpdate: new Date(),
                nextUpdate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 ngày sau
                revokedCertificates: [],
                crlNumber: 1,
                crlPem: crlPem
            });
        }

        // Thêm chứng chỉ bị thu hồi vào CRL
        const newRevokedCert = {
            deviceId,
            serialNumber: serial,
            revocationDate: new Date(),
            reason: 'keyCompromise',
            issuer: caCertPem
        };

        

        // Cập nhật CRL trong database
        await crl.updateCRL([newRevokedCert], fs.readFileSync(caKeyPath, 'utf8'));

        // Publish revoke request
        const revokeTopic = `iot/${deviceId}/revoke_cert`;
        const confirmTopic = `iot/${deviceId}/revoke_confirmation`;
        const revokeMessage = {
            device_id: deviceId,
            serial,
            request: 'revoke_certificate',
            crl_pem: crlPem // Gửi cả CRL PEM cho device
        };

        const confirmationTimeout = 30000;
        const confirmationPromise = new Promise((resolve, reject) => {
            const handler = (topic, message) => {
                if (topic === confirmTopic) {
                    try {
                        const confirmation = JSON.parse(message.toString());
                        if (confirmation.device_id === deviceId) {
                            messageHandlers.splice(messageHandlers.indexOf(handler), 1);
                            resolve(confirmation);
                        }
                    } catch (err) {
                        console.error(`Error parsing revoke confirmation for ${deviceId}:`, err.message);
                    }
                }
            };

            const messageHandlers = [];
            onMessage(handler);
            messageHandlers.push(handler);

            setTimeout(() => {
                messageHandlers.splice(messageHandlers.indexOf(handler), 1);
                reject(new Error(`Timeout waiting for revoke confirmation from ${deviceId}`));
            }, confirmationTimeout);
        });

        await new Promise((resolve, reject) => {
            publish(revokeTopic, JSON.stringify(revokeMessage), { qos: 1 }, (err) => {
                if (err) {
                    console.error(`Failed to publish revoke request to ${revokeTopic}:`, err.message);
                    reject(new Error('Failed to send revoke request to device'));
                } else {
                    console.log(`Sent revoke request to ${revokeTopic}:`, revokeMessage);
                    resolve();
                }
            });
        });

        // Wait for confirmation
        const confirmation = await confirmationPromise;
        if (confirmation.status !== 'success') {
            throw new Error(`Revocation failed on device ${deviceId}: ${confirmation.message || 'Unknown error'}`);
        }

        // Update device status after confirmation
        await Device.findOneAndUpdate(
            { device_id: deviceId, serial },
            { status: 'revoked' }
        );
        console.log(`Updated Device collection for ${deviceId} with revoked status`);

        return {
            crl_hex: revokeResult.crl_hex,
            crl_pem: crlPem, // Thêm CRL PEM vào kết quả
            expiry: revokeResult.expiry,
            confirmation
        };
    } catch (err) {
        console.error('Error in revokeCertificate service:', err.message);
        throw err;
    }
};

// Hàm mới để kiểm tra chứng chỉ có bị thu hồi không
const isCertificateRevoked = async (serialNumber, issuerPem) => {
    try {
        return await CRL.isCertificateRevoked(serialNumber, issuerPem);
    } catch (err) {
        console.error('Error checking certificate revocation status:', err);
        throw err;
    }
};

module.exports = { renewCertificate, verifySensorData, revokeCertificate, isCertificateRevoked };