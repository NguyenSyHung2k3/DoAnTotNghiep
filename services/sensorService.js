const SensorData = require('../models/SensorData');
const Logger = require('../utils/logger');

const getAllSensors = async ({ limit = 100, skip = 0 }) => {
  try {
    const data = await SensorData.find()
      .sort({ timestamp: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit))
      .lean();
    Logger.info(`Retrieved ${data.length} sensor data records`);
    return data;
  } catch (err) {
    Logger.error('Error in getAllSensors:', err.message);
    throw err;
  }
};

const getSensorsByDeviceId = async ({ device_id, limit = 100, skip = 0 }) => {
  try {
    const data = await SensorData.find({ device_id })
      .sort({ timestamp: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit))
      .lean();
    Logger.info(`Retrieved ${data.length} sensor data records for device ${device_id}`);
    return data;
  } catch (err) {
    Logger.error('Error in getSensorsByDeviceId:', err.message);
    throw err;
  }
};

module.exports = {
  getAllSensors,
  getSensorsByDeviceId
};