const Device = require('../../models/Device');
const SensorData = require('../../models/SensorData');
const EncryptedSensorData = require('../../models/EncryptedSensorData');
const socketHandler = require('../../websocket/socketHandler');
const { logMqtt, logSystem, logError } = require('../../utils/logger');

// Import the three handleSensorData functions from the provided files
const presentCbcHandler = require('./PRESENT/sensorDataHandler');
const aesCbcHmacHandler = require('./AES/sensorDataHandler');
const chachaPolyHandler = require('./ChaChaPoly/sensorDataHandler');

async function dispatchSensorData(deviceId, data) {
  logMqtt.info(`Dispatching sensor data for device ${deviceId}`, { data });
  const { device_id, ciphertext, tag, iv, nonce, encryption_type } = data;

  // Validate device ID consistency
  if (device_id !== deviceId) {
    logMqtt.error(`Device ID mismatch`, { 
      payload_device_id: device_id, 
      topic_device_id: deviceId 
    });
    return;
  }

  // Validate required fields
  const hasRequiredFields = device_id && ciphertext && tag && 
    (encryption_type === 'present-cbc' ? iv : nonce);
  if (!hasRequiredFields) {
    logMqtt.error(`Missing or invalid sensor data`, { 
      device_id, 
      has_ciphertext: !!ciphertext, 
      has_tag: !!tag, 
      has_iv: !!iv, 
      has_nonce: !!nonce, 
      encryption_type 
    });
    socketHandler.broadcastError(deviceId, new Error('Missing or invalid data'));
    return;
  }

  logMqtt.debug(`Dispatching sensor data`, { 
    device_id, 
    ciphertext_length: ciphertext.length, 
    tag, 
    iv, 
    nonce, 
    encryption_type 
  });

  // Dispatch to appropriate handler based on encryption type
  try {
    switch (encryption_type) {
      case 'present-cbc':
        await presentCbcHandler.handleSensorData(deviceId, data);
        logSystem.info(`Dispatched to present-cbc handler`, { device_id: deviceId, encryption_type });
        break;
      case 'aes128-cbc-hmac':
        await aesCbcHmacHandler.handleSensorData(deviceId, data);
        logSystem.info(`Dispatched to aes128-cbc-hmac handler`, { device_id: deviceId, encryption_type });
        break;
      case 'chachapoly':
        await chachaPolyHandler.handleSensorData(deviceId, data);
        logSystem.info(`Dispatched to chachapoly handler`, { device_id: deviceId, encryption_type });
        break;
      default:
        logError.error(`Unsupported encryption type`, { 
          device_id: deviceId, 
          encryption_type 
        });
        socketHandler.broadcastError(deviceId, new Error('Unsupported encryption type'));
        return;
    }
  } catch (err) {
    logError.error(`Failed to dispatch sensor data`, { 
      device_id: deviceId, 
      encryption_type, 
      error: err.message, 
      stack: err.stack 
    });
    socketHandler.broadcastError(deviceId, err);
  }
}

module.exports = { dispatchSensorData };