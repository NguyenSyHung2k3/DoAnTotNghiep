const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  device_id: { type: String, required: true, unique: true },
  serial: { type: String, required: true, unique: true },
  certificate: { type: String, required: true },
  public_key_x: { type: String, required: true },
  public_key_y: { type: String, required: true },
  shared_secret: { type: String },
  registered_at: { type: Date, default: Date.now },
  expiry: { type: String, required: true }, // ISO 8601 format (e.g., "2026-05-12T00:00:00Z")
  status: { 
    type: String, 
    enum: ['active', 'expired', 'revoked'], 
    default: 'active' 
  }
});

module.exports = mongoose.model('Device', DeviceSchema);