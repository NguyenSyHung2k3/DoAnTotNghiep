const Device = require('../../../models/Device');
const SensorData = require('../../../models/SensorData');
const EncryptedSensorData = require('../../../models/EncryptedSensorData');
const socketHandler = require('../../../websocket/socketHandler');
const cryptoUtils = require('../../../crypto/AESCryptoUtils/cryptoUtils');
const { sharedSecrets } = require('../../deviceKeyHandler');
const { verifySensorData } = require('../../../services/certService');
const { publish } = require('../../mqttClient');
const { logMqtt, logSystem, logError } = require('../../../utils/logger');

async function handleSensorData(deviceId, data) {
  logMqtt.info(`Processing sensor data for device ${deviceId}`, { data });
  const { device_id, ciphertext, tag, nonce } = data;
  
  socketHandler.broadcastEncryptedData(deviceId, {
        device_id: deviceId,
        ciphertext: data.ciphertext,
        tag: data.tag,
        nonce: data.nonce,
        encryption_type: data.encryption_type,
        encryption_time_us: data.encryption_time_us,
        encryption_energy_uj: data.encryption_energy_uj,
        plaintext_size_bytes: data.plaintext_size_bytes,
        ciphertext_size_bytes: data.ciphertext_size_bytes,
        cycles_per_byte: data.cycles_per_byte,
        total_cycles: data.total_cycles
  });

  if (device_id !== deviceId) {
    logMqtt.error(`Device ID mismatch`, { 
      payload_device_id: device_id, 
      topic_device_id: deviceId 
    });
    return;
  }

  if (!device_id || !ciphertext || !tag || !nonce ) {
    logMqtt.error(`Missing required sensor data`, { 
      device_id, 
      has_ciphertext: !!ciphertext, 
      has_tag: !!tag, 
      has_nonce: !!nonce 
    });
    socketHandler.broadcastError(deviceId, new Error('Missing required data'));
    return;
  }

  logMqtt.debug(`Received sensor data`, { 
    device_id, 
    ciphertext_length: ciphertext.length,
    tag,
    nonce 
  });

  let sharedSecret = sharedSecrets.get(deviceId);
  if (!sharedSecret) {
    logSystem.info(`No shared secret in memory, checking database`, { device_id: deviceId });
    const device = await Device.findOne({ device_id: deviceId });
    if (device && device.shared_secret) {
      sharedSecret = Buffer.from(device.shared_secret, 'hex');
      sharedSecrets.set(deviceId, sharedSecret);
      logSystem.info(`Restored shared secret from database`, { device_id: deviceId });
    } else {
      logError.error(`No shared secret found`, { 
        device_id: deviceId,
        has_device: !!device,
        has_shared_secret: !!(device && device.shared_secret)
      });
      socketHandler.broadcastError(deviceId, new Error('No shared secret found'));
      return;
    }
  }

  const device = await Device.findOne({ device_id: deviceId });
  if (!device || device.status !== 'active') {
    logError.error(`Device not active or missing`, { 
      device_id: deviceId,
      status: device ? device.status : 'missing'
    });
    socketHandler.broadcastError(deviceId, new Error(`Certificate is ${device ? device.status : 'missing'}`));
    return;
  }

  const decryptionResult = await cryptoUtils.decryptData(ciphertext, tag, nonce, sharedSecret);
  if (!decryptionResult || decryptionResult.status !== 'success') {
    logError.error(`Decryption failed`, { 
      device_id: deviceId,
      status: decryptionResult ? decryptionResult.status : 'no result'
    });
    socketHandler.broadcastError(deviceId, new Error('Decryption failed'));
    return;
  }

  const decrypted = decryptionResult.data;
  logMqtt.info(`Successfully decrypted data`, { 
    device_id: deviceId,
    decrypted_data: decrypted
  });

  try {
    const sensorData = new SensorData({
      device_id,
      temperature: decrypted.temperature,
      humidity: decrypted.humidity,
      wifi_rssi: decrypted.wifi_rssi,
      encryption_time_us: decrypted.encryption_time_us,
      encryption_energy_uj: decrypted.encryption_energy_uj,
      plaintext_size_bytes: decrypted.plaintext_size_bytes,
      ciphertext_size_bytes: decrypted.ciphertext_size_bytes,
      encryption_type: decrypted.encryption_type,
      nonce: nonce,
      tag: tag,
      cycles_per_byte: decrypted.cycles_per_byte,
      total_cycles: decrypted.total_cycles,
      timestamp: decrypted.timestamp
    });
    await sensorData.save();
    logSystem.info(`Saved sensor data to database`, { 
      device_id: deviceId,
      sensor_data: sensorData
    });

    // Publish decrypted data to MQTT
    const processedDataTopic = `iot/${deviceId}/processed_data`;
    const processedData = {
      device_id: deviceId,
      temperature: decrypted.temperature,
      humidity: decrypted.humidity,
      wifi_rssi: decrypted.wifi_rssi,
      encryption_time_us: decrypted.encryption_time_us,
      encryption_energy_uj: decrypted.encryption_energy_uj,
      plaintext_size_bytes: decrypted.plaintext_size_bytes,
      ciphertext_size_bytes: decrypted.ciphertext_size_bytes,
      encryption_type: decrypted.encryption_type,
      timestamp: decrypted.timestamp
    };
    
    publish(processedDataTopic, JSON.stringify(processedData), (err) => {
      if (err) {
        logMqtt.error(`Failed to publish processed data`, { 
          device_id: deviceId,
          topic: processedDataTopic,
          error: err.message
        });
      } else {
        logMqtt.info(`Published processed data`, { 
          device_id: deviceId,
          topic: processedDataTopic,
          data: processedData
        });
      }
    });

    socketHandler.broadcastSensorData(deviceId, {
      temperature: decrypted.temperature,
      humidity: decrypted.humidity,
      wifi_rssi: decrypted.wifi_rssi,
      encryption_time_us: decrypted.encryption_time_us,
      encryption_energy_uj: decrypted.encryption_energy_uj,
      plaintext_size_bytes: decrypted.plaintext_size_bytes,
      ciphertext_size_bytes: decrypted.ciphertext_size_bytes,
      encryption_type: decrypted.encryption_type,
      nonce: nonce,
      tag: tag,
      cycles_per_byte: decrypted.cycles_per_byte,
      total_cycles: decrypted.total_cycles,
      timestamp: decrypted.timestamp
    });

    await EncryptedSensorData.findOneAndUpdate(
      { device_id, encrypted_data: ciphertext, nonce },
      {
        is_decrypted: true,
        decrypted_at: new Date()
      }
    );
    logSystem.info(`Updated decryption status`, { device_id: deviceId });
  } catch (err) {
    logError.error(`Failed to process sensor data`, { 
      device_id: deviceId,
      error: err.message,
      stack: err.stack
    });
    socketHandler.broadcastError(deviceId, err);
    try {
      await EncryptedSensorData.findOneAndUpdate(
        { device_id, encrypted_data: ciphertext, nonce },
        {
          error_message: 'Failed to save decrypted data',
          is_decrypted: false
        }
      );
      logSystem.info(`Updated encryption status after error`, { device_id: deviceId });
    } catch (updateErr) {
      logError.error(`Failed to update encryption status`, { 
        device_id: deviceId,
        error: updateErr.message,
        stack: updateErr.stack
      });
    }
  }
}

module.exports = { handleSensorData };