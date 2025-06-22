const mongoose = require('mongoose');

const CertConfirmationSchema = new mongoose.Schema({
  device_id: { type: String, required: true, index: true },
  status: { type: String, enum: ['success', 'error'], required: true },
  certificate_hash: { type: String, required: true }, // SHA-256 hash of certificate
  message: { type: String }, // Optional error message if status is 'error'
  timestamp: { type: Date, required: true },
  created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('CertConfirmation', CertConfirmationSchema);