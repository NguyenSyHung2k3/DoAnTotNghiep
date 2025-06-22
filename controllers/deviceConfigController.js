const { publish } = require('../mqtt/mqttClient');
const { logMqtt, logError } = require('../utils/logger');

const sendDeviceConfig = async (req, res) => {
  try {
    const { device_id, device_id_recv } = req.params;
    const config = req.body;

    if (!device_id || !device_id_recv) {
      return res.status(400).json({
        success: false,
        message: 'Device ID and receiver Device ID are required'
      });
    }

    // Tạo payload config
    const configPayload = {
      device_id,
      device_id_recv,
      config,
      timestamp: new Date().toISOString()
    };

    // Topic để gửi config - sử dụng device_id_recv
    const configTopic = `iot/${device_id_recv}/config`;

    // Publish config lên MQTT
    publish(configTopic, JSON.stringify(configPayload), (err) => {
      if (err) {
        logMqtt.error('Failed to publish device config', {
          device_id,
          device_id_recv,
          error: err.message
        });
        return res.status(500).json({
          success: false,
          message: 'Failed to send configuration',
          error: err.message
        });
      }

      logMqtt.info('Published device config', {
        device_id,
        device_id_recv,
        config: configPayload
      });

      res.status(200).json({
        success: true,
        message: 'Configuration sent successfully',
        data: {
          device_id,
          device_id_recv,
          config: configPayload
        }
      });
    });
  } catch (error) {
    logError.error('Error in sendDeviceConfig', {
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

module.exports = {
  sendDeviceConfig
}; 