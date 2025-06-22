const { onMessage, subscribeToDeviceTopics } = require('./mqttClient');
const deviceKeyHandler = require('./deviceKeyHandler');
const PresentSensorDataHandler = require('./dataHandler/PRESENT/sensorDataHandler');
const AESSensorDataHandler = require('./dataHandler/AES/sensorDataHandler');
const ChaChaPolySensorDataHandler = require('./dataHandler/ChaChaPoly/sensorDataHandler');
const certRenewalHandler = require('./certRenewalHandler');
const certConfirmationHandler = require('./certConfirmationHandler');
const { updateDeviceStatuses } = require('./utils/dbUtils');
const Device = require('../models/Device');

async function initialize() {
  try {
    // Load devices and subscribe to their topics
    const devices = await Device.find({}, 'device_id');
    const deviceIds = devices.map(device => device.device_id);
    console.log(`Found ${deviceIds.length} devices in database:`, deviceIds);
    if (deviceIds.length > 0) {
      subscribeToDeviceTopics(deviceIds);
    }

    // Update device certificate statuses based on expiry
    // await updateDeviceStatuses();
  } catch (err) {
    console.error('Error initializing MQTT handler:', err.message);
  }

  // Route incoming MQTT messages
  onMessage(async (topic, message) => {
    try {
      console.log(`Processing message on topic ${topic}`);
      const topicParts = topic.split('/');
      if (topicParts.length !== 3 || topicParts[0] !== 'iot') {
        console.log(`No handler for topic ${topic}`);
        return;
      }

      const deviceId = topicParts[1];
      const subTopic = topicParts[2];
      const data = JSON.parse(message.toString());
      console.log(`Parsed message on topic ${topic}:`, data);

      

      if (subTopic === 'device_key') {
        await deviceKeyHandler.handleDeviceKey(deviceId, data);
      } else if (subTopic === 'sensors') {
        switch(data.encryption_type) {
          case 'present-cbc':
            await PresentSensorDataHandler.handleSensorData(deviceId, data);
            break;
          case 'chachapoly':
            await ChaChaPolySensorDataHandler.handleSensorData(deviceId, data);
            break;
          case 'aes-128-cbc':
            await AESSensorDataHandler.handleSensorData(deviceId, data);
            break;
          default:
            throw new Error(`Unsupported encryption type: ${data.encryption_type}`);
        }
      } else if (subTopic === 'renew_cert') {
        await certRenewalHandler.handleCertificateRenewal(deviceId, data);
      } else if (subTopic === 'cert_confirmation') {
        await certConfirmationHandler.handleCertConfirmation(deviceId, data);
      } else {
        console.log(`No handler for subtopic ${subTopic} on topic ${topic}`);
      }
    } catch (err) {
      console.error(`Error processing MQTT message on topic ${topic}:`, err.message);
    }
  });
}

module.exports = { initialize };