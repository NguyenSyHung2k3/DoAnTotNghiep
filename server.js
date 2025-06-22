const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketHandler = require('./websocket/socketHandler');
const morgan = require('morgan');
const { mongoConfig } = require('./config/config');
const MqttHandler = require('./mqtt/mqttHandler');
const certRoutes = require('./routes/certRoutes');
const deviceConfigRoutes = require('./routes/deviceConfigRoutes');
const subcriberRoutes = require('./routes/subscriberRoutes');
const deviceRoutes = require('./routes/deviceRoutes');
const logger = require('./utils/logger');
const { initializeMqttClient } = require('./mqtt/mqttClient');
const { initialize: initializeMqttHandler } = require('./mqtt/mqttHandler');
const path = require('path');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

// Khởi tạo WebSocket
socketHandler.initialize(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', certRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/sensors', require('./routes/sensorRoutes'));
app.use('/api/device-config', deviceConfigRoutes);
// Use morgan with winston logger
app.use(morgan('combined', { stream: logger.stream }));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
    error: err.message
  });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/iot_encryption')
  .then(() => {
    console.log('Connected to MongoDB');
    server.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
      console.log(`WebSocket client available at http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to connect to MongoDB:', err);
    process.exit(1);
  });

initializeMqttClient();
initializeMqttHandler();

