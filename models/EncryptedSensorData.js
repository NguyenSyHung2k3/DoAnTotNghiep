const mongoose = require('mongoose');

const encryptedSensorDataSchema = new mongoose.Schema({
  device_id: { type: String, required: true },
  encrypted_data: { type: String, required: true }, // Dữ liệu đã mã hóa (ciphertext)
  iv: { type: String, required: true }, // Initialization Vector cho mã hóa
  nonce: { type: String, required: true }, // Nonce cho mã hóa
  tag: { type: String, required: true }, // Authentication tag
  encryption_type: { 
    type: String, 
    required: true,
    enum: ['AES-GCM', 'AES-CCM', 'ChaCha20-Poly1305'], // Các loại mã hóa được hỗ trợ
    default: 'AES-GCM'
  },
  received_at: { type: Date, required: true, default: Date.now }, // Thời điểm nhận dữ liệu
  timestamp: { type: Date, required: true, default: Date.now }, // Thời điểm dữ liệu được tạo
  is_decrypted: { type: Boolean, default: false }, // Trạng thái đã giải mã hay chưa
  decrypted_at: { type: Date }, // Thời điểm giải mã
  error_message: { type: String } // Thông báo lỗi nếu có trong quá trình giải mã
});

// Index để tối ưu truy vấn
encryptedSensorDataSchema.index({ device_id: 1, timestamp: -1 });
encryptedSensorDataSchema.index({ is_decrypted: 1 });
encryptedSensorDataSchema.index({ received_at: -1 });
encryptedSensorDataSchema.index({ encryption_type: 1 });

module.exports = mongoose.model('EncryptedSensorData', encryptedSensorDataSchema); 