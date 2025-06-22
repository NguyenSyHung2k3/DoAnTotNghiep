const { logSystem, logError } = require('../utils/logger');
const Device = require('../models/Device');
const crypto = require('crypto');
const { restartMQTTConnection } = require('../mqtt/mqttClient');

const generateDefaultValues = (device_id) => {
  const serial = `SER${device_id}_${Date.now()}`;
  const certificate = `CERT_${device_id}_${crypto.randomBytes(16).toString('hex')}`;
  const public_key_x = `PKX_${device_id}_${crypto.randomBytes(16).toString('hex')}`;
  const public_key_y = `PKY_${device_id}_${crypto.randomBytes(16).toString('hex')}`;
  const shared_secret = crypto.randomBytes(32).toString('hex');
  
  const expiry = new Date();
  expiry.setFullYear(expiry.getFullYear() + 1);
  
  return {
    serial,
    certificate,
    public_key_x,
    public_key_y,
    shared_secret,
    expiry: expiry.toISOString()
  };
};

const registerDevice = async (req, res) => {
  try {
    const { device_id } = req.body;

    if (!device_id) {
      return res.status(400).json({
        success: false,
        message: 'Device ID is required'
      });
    }

    const existingDevice = await Device.findOne({ device_id });
    if (existingDevice) {
      return res.status(400).json({
        success: false,
        message: 'Device already registered'
      });
    }

    const defaultValues = generateDefaultValues(device_id);

    const newDevice = new Device({
      device_id,
      ...defaultValues,
      status: 'active'
    });

    await newDevice.save();

    try {
      await restartMQTTConnection();
      logSystem.info('MQTT connection restarted after new device registration', {
        device_id
      });
    } catch (mqttError) {
      logError.error('Failed to restart MQTT connection', {
        device_id,
        error: mqttError.message
      });
    }

    logSystem.info('New device registered', {
      device_id,
      serial: defaultValues.serial
    });

    res.status(201).json({
      success: true,
      message: 'Device registered successfully',
      data: newDevice
    });
  } catch (error) {
    logError.error('Error in registerDevice', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

const deleteDevice = async (req, res) => {
  try {
    const { device_id } = req.params;

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    await Device.deleteOne({ device_id });

    try {
      await restartMQTTConnection();
      logSystem.info('MQTT connection restarted after device deletion', {
        device_id
      });
    } catch (mqttError) {
      logError.error('Failed to restart MQTT connection', {
        device_id,
        error: mqttError.message
      });
    }

    logSystem.info('Device deleted', {
      device_id
    });

    res.status(200).json({
      success: true,
      message: 'Device deleted successfully'
    });
  } catch (error) {
    logError.error('Error in deleteDevice', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

const getDevice = async (req, res) => {
  try {

    const { device_id } = req.params;

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    res.status(200).json({
      success: true,
      data: device
    });
  } catch (error) {
    logError.error('Error in getDevice', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

const getDevicesAll = async (req, res) => {
  try{
      const devices = await Device.find({});

      res.status(200).json({
        success: true,
        data: devices
      })
  } catch (error) {

    logError.error('Error in getDevicesAll', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }

}

module.exports = {
  registerDevice,
  deleteDevice,
  getDevice,
  getDevicesAll
}; 