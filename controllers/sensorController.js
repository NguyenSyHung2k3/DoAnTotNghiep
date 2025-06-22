const SensorDataService = require('../services/sensorService');

const getAllSensors = async (req, res) => {
  try {
    const { 
      limit = 100, 
      skip = 0, 
      startDate, 
      endDate,
      encryptionType 
    } = req.query;

    const data = await SensorDataService.getAllSensors({ 
      limit: parseInt(limit), 
      skip: parseInt(skip),
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      encryptionType
    });
    
    res.status(200).json({
      success: true,
      data: data.sensors,
      pagination: {
        total: data.total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: data.total > (parseInt(skip) + parseInt(limit))
      }
    });
  } catch (err) {
    console.error('Error in getAllSensors:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

const getSensorsByDeviceId = async (req, res) => {
  try {
    const { device_id } = req.params;
    const { 
      limit = 100, 
      skip = 0, 
      startDate, 
      endDate,
      encryptionType 
    } = req.query;
    
    if (!device_id) {
      return res.status(400).json({
        success: false,
        message: 'Device ID is required'
      });
    }

    const data = await SensorDataService.getSensorsByDeviceId({ 
      device_id, 
      limit: parseInt(limit), 
      skip: parseInt(skip),
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      encryptionType
    });

    if (!data.sensors.length) {
      return res.status(404).json({
        success: false,
        message: 'No sensor data found for this device'
      });
    }

    res.status(200).json({
      success: true,
      data: data.sensors,
      pagination: {
        total: data.total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: data.total > (parseInt(skip) + parseInt(limit))
      }
    });
  } catch (err) {
    console.error('Error in getSensorsByDeviceId:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

const getEncryptionStats = async (req, res) => {
  try {
    const stats = await SensorDataService.getEncryptionTypeStats();

    res.status(200).json({
      success: true,
      data: {
        encryption_types: stats.map(stat => ({
          type: stat._id,
          count: stat.count,
          energy_usage: {
            average: stat.avg_energy,
            minimum: stat.min_energy,
            maximum: stat.max_energy
          }
        }))
      }
    });
  } catch (err) {
    console.error('Error in getEncryptionStats:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

module.exports = {
  getAllSensors,
  getSensorsByDeviceId,
  getEncryptionStats
};