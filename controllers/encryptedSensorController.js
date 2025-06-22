const EncryptedSensorDataService = require('../services/encryptedSensorService');

const saveEncryptedData = async (req, res) => {
  try {
    const data = req.body;
    
    // Validate required fields
    if (!data.device_id || !data.ciphertext || !data.nonce || !data.tag) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: device_id, ciphertext, nonce, and tag are required'
      });
    }

    const savedData = await EncryptedSensorDataService.saveEncryptedData(data);
    
    res.status(201).json({
      success: true,
      data: savedData
    });
  } catch (err) {
    console.error('Error in saveEncryptedData:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

const getAllEncryptedData = async (req, res) => {
  try {
    const { 
      limit = 100, 
      skip = 0, 
      startDate, 
      endDate,
      isDecrypted,
      encryptionType 
    } = req.query;

    const data = await EncryptedSensorDataService.getAllEncryptedData({ 
      limit: parseInt(limit), 
      skip: parseInt(skip),
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      isDecrypted: isDecrypted === 'true' ? true : isDecrypted === 'false' ? false : undefined,
      encryptionType
    });
    
    res.status(200).json({
      success: true,
      data: data.data,
      pagination: {
        total: data.total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: data.total > (parseInt(skip) + parseInt(limit))
      }
    });
  } catch (err) {
    console.error('Error in getAllEncryptedData:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

const getEncryptedDataByDeviceId = async (req, res) => {
  try {
    const { device_id } = req.params;
    const { 
      limit = 100, 
      skip = 0, 
      startDate, 
      endDate,
      isDecrypted,
      encryptionType 
    } = req.query;
    
    if (!device_id) {
      return res.status(400).json({
        success: false,
        message: 'Device ID is required'
      });
    }

    const data = await EncryptedSensorDataService.getEncryptedDataByDeviceId({ 
      device_id, 
      limit: parseInt(limit), 
      skip: parseInt(skip),
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      isDecrypted: isDecrypted === 'true' ? true : isDecrypted === 'false' ? false : undefined,
      encryptionType
    });

    if (!data.data.length) {
      return res.status(404).json({
        success: false,
        message: 'No encrypted data found for this device'
      });
    }

    res.status(200).json({
      success: true,
      data: data.data,
      pagination: {
        total: data.total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: data.total > (parseInt(skip) + parseInt(limit))
      }
    });
  } catch (err) {
    console.error('Error in getEncryptedDataByDeviceId:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

const getDecryptionStats = async (req, res) => {
  try {
    const [pendingCount, failedCount, encryptionTypeStats] = await Promise.all([
      EncryptedSensorDataService.getPendingDecryptionCount(),
      EncryptedSensorDataService.getFailedDecryptionCount(),
      EncryptedSensorDataService.getEncryptionTypeStats()
    ]);

    res.status(200).json({
      success: true,
      data: {
        pending_decryption: pendingCount,
        failed_decryption: failedCount,
        encryption_types: encryptionTypeStats
      }
    });
  } catch (err) {
    console.error('Error in getDecryptionStats:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: err.message 
    });
  }
};

module.exports = {
  saveEncryptedData,
  getAllEncryptedData,
  getEncryptedDataByDeviceId,
  getDecryptionStats
}; 