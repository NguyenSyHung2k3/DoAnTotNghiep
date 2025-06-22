const mongoose = require('mongoose');

const sensorDataSchema = new mongoose.Schema({
  device_id: {
    type: String,
    required: true,
    index: true
  },
  temperature: {
    type: Number,
    required: true
  },
  humidity: {
    type: Number,
    required: true
  },
  wifi_rssi: {
    type: Number,
    required: true
  },
  encryption_time_us: {
    type: Number,
    required: false
  },
  encryption_energy_uj: {
    type: Number,
    required: false
  },
  plaintext_size_bytes: {
    type: Number,
    required: false
  },
  ciphertext_size_bytes: {
    type: Number,
    required: false
  },
  encryption_type: {
    type: String,
    required: false,
    enum: ['chachapoly', 'present-cbc', 'aes128-cbc-hmac']
  },
  nonce: {
    type: String,
    required: false
  },
  tag: {
    type: String,
    required: false
  },
  cycles_per_byte: {
    type: Number,
    required: false
  },
  total_cycles: {
    type: Number,
    required: false
  },
  timestamp: {
    type: String,
    required: true,
    index: true
  }
}, {
  timestamps: true
});

// Indexes
sensorDataSchema.index({ device_id: 1, timestamp: -1 });
sensorDataSchema.index({ encryption_type: 1 });

const SensorData = mongoose.model('SensorData', sensorDataSchema);

module.exports = SensorData;