const socketIO = require('socket.io');
const { logError } = require('../utils/logger');

let io;
const rateLimit = new Map(); // In-memory rate limiter
const RATE_LIMIT = { max: 10, windowMs: 60000 }; // 10 actions per minute

function initialize(server) {
  io = socketIO(server, {
    cors: {
      origin: process.env.CORS_ORIGIN || "*",
      methods: ["GET", "POST"]
    }
  });

  io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);

    // Rate-limiting check function
    const checkRateLimit = (action) => {
      const now = Date.now();
      const client = rateLimit.get(socket.id) || { count: 0, resetTime: now + RATE_LIMIT.windowMs };
      if (now > client.resetTime) {
        client.count = 0;
        client.resetTime = now + RATE_LIMIT.windowMs;
      }
      if (client.count >= RATE_LIMIT.max) {
        logError.error(`Rate limit exceeded for ${action} by client ${socket.id}`);
        socket.emit('error', { message: `Rate limit exceeded for ${action}. Try again later.` });
        return false;
      }
      client.count++;
      rateLimit.set(socket.id, client);
      return true;
    };

    socket.on('subscribe_device', (deviceId) => {
      if (!checkRateLimit('subscribe_device')) return;
      if (!deviceId) {
        logError.error(`Invalid deviceId for subscription by client ${socket.id}`);
        socket.emit('error', { message: 'Invalid deviceId' });
        return;
      }
      socket.join(`device_${deviceId}`);
      console.log(`Client ${socket.id} subscribed to device ${deviceId}`);
    });

    socket.on('unsubscribe_device', (deviceId) => {
      if (!checkRateLimit('unsubscribe_device')) return;
      if (!deviceId) {
        logError.error(`Invalid deviceId for unsubscription by client ${socket.id}`);
        socket.emit('error', { message: 'Invalid deviceId' });
        return;
      }
      socket.leave(`device_${deviceId}`);
      console.log(`Client ${socket.id} unsubscribed from device ${deviceId}`);
    });

    // Xử lý khi client ngắt kết nối
    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
      rateLimit.delete(socket.id); // Clean up rate limit data
    });

    // Handle socket errors
    socket.on('error', (error) => {
      logError.error(`Socket error for client ${socket.id}: ${error.message}`);
    });
  });

  return io;
}

// Hàm gửi dữ liệu sensor mới đến các client đang theo dõi
function broadcastSensorData(deviceId, data) {
  if (!io) {
    logError.error('Socket.IO not initialized');
    return;
  }
  if (!deviceId || !data) {
    logError.error('Invalid deviceId or data for broadcasting sensor data');
    return;
  }
  io.to(`device_${deviceId}`).emit('sensor_data', {
    device_id: deviceId,
    ...data,
    timestamp: new Date().toISOString()
  });
}

function broadcastEncryptedData(deviceId, data) {
  if (!io) {
    logError.error('Socket.IO not initialized');
    return;
  }
  if (!deviceId || !data) {
    logError.error('Invalid deviceId or data for broadcasting encrypted data');
    return;
  }
  io.to(`device_${deviceId}`).emit('encrypted_data', {
    device_id: deviceId,
    ...data,
    timestamp: new Date().toISOString()
  });
}

function broadcastDeviceStatus(deviceId, statusData) {
  if (!io) {
    logError.error('Socket.IO not initialized');
    return;
  }
  if (!deviceId || !statusData) {
    logError.error('Invalid deviceId or statusData for broadcasting device status');
    return;
  }
  io.to(`device_${deviceId}`).emit('device_status', {
    device_id: deviceId,
    ...statusData,
    timestamp: new Date().toISOString()
  });
}

// Hàm gửi thông báo lỗi đến các client đang theo dõi
function broadcastError(deviceId, error) {
  if (!io) {
    logError.error('Socket.IO not initialized');
    return;
  }
  if (!deviceId || !error || !error.message) {
    logError.error('Invalid deviceId or error for broadcasting error');
    return;
  }
  io.to(`device_${deviceId}`).emit('error', {
    device_id: deviceId,
    error: error.message,
    timestamp: new Date().toISOString()
  });
}

// Hàm gửi thông tin về trạng thái giải mã
function broadcastDecryptionStatus(deviceId, status) {
  if (!io) {
    logError.error('Socket.IO not initialized');
    return;
  }
  if (!deviceId || !status) {
    logError.error('Invalid deviceId or status for broadcasting decryption status');
    return;
  }
  io.to(`device_${deviceId}`).emit('decryption_status', {
    device_id: deviceId,
    ...status,
    timestamp: new Date().toISOString()
  });
}

module.exports = {
  initialize,
  broadcastSensorData,
  broadcastError,
  broadcastDecryptionStatus,
  broadcastEncryptedData,
  broadcastDeviceStatus
};