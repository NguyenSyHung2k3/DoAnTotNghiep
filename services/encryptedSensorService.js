const EncryptedSensorData = require('../models/EncryptedSensorData');
const Logger = require('../utils/logger');

class EncryptedSensorDataService {
  static async saveEncryptedData(data) {
    try {
      const encryptedData = new EncryptedSensorData({
        device_id: data.device_id,
        encrypted_data: data.ciphertext,
        iv: data.nonce, // Sử dụng nonce làm IV
        nonce: data.nonce,
        tag: data.tag,
        encryption_type: 'AES-GCM', // Mặc định là AES-GCM
        received_at: new Date(),
        timestamp: new Date() // Có thể được cập nhật từ dữ liệu giải mã
      });

      await encryptedData.save();
      Logger.info(`Saved encrypted data for device ${data.device_id}`);
      return encryptedData;
    } catch (error) {
      Logger.error('Error saving encrypted data:', error);
      throw error;
    }
  }

  static async getAllEncryptedData({ limit = 100, skip = 0, startDate, endDate, isDecrypted, encryptionType }) {
    const query = {};
    
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = startDate;
      if (endDate) query.timestamp.$lte = endDate;
    }

    if (isDecrypted !== undefined) {
      query.is_decrypted = isDecrypted;
    }

    if (encryptionType) {
      query.encryption_type = encryptionType;
    }

    const [data, total] = await Promise.all([
      EncryptedSensorData.find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit),
      EncryptedSensorData.countDocuments(query)
    ]);

    return { data, total };
  }

  static async getEncryptedDataByDeviceId({ device_id, limit = 100, skip = 0, startDate, endDate, isDecrypted, encryptionType }) {
    const query = { device_id };
    
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = startDate;
      if (endDate) query.timestamp.$lte = endDate;
    }

    if (isDecrypted !== undefined) {
      query.is_decrypted = isDecrypted;
    }

    if (encryptionType) {
      query.encryption_type = encryptionType;
    }

    const [data, total] = await Promise.all([
      EncryptedSensorData.find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit),
      EncryptedSensorData.countDocuments(query)
    ]);

    return { data, total };
  }

  static async getPendingDecryptionCount() {
    return EncryptedSensorData.countDocuments({ is_decrypted: false });
  }

  static async getFailedDecryptionCount() {
    return EncryptedSensorData.countDocuments({ 
      is_decrypted: false,
      error_message: { $exists: true, $ne: null }
    });
  }

  static async getEncryptionTypeStats() {
    return EncryptedSensorData.aggregate([
      {
        $group: {
          _id: '$encryption_type',
          count: { $sum: 1 },
          decrypted: {
            $sum: { $cond: [{ $eq: ['$is_decrypted', true] }, 1, 0] }
          },
          failed: {
            $sum: {
              $cond: [
                { $and: [
                  { $eq: ['$is_decrypted', false] },
                  { $ne: ['$error_message', null] }
                ]},
                1,
                0
              ]
            }
          }
        }
      }
    ]);
  }
}

module.exports = EncryptedSensorDataService; 