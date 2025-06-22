const socketIO = require('socket.io');
let io;

function initialize(server) {
  io = socketIO(server, {
    cors: {
      origin: "*", // Cho phép tất cả các origin trong môi trường development
      methods: ["GET", "POST"]
    }
  });

  io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);

    // Xử lý khi client đăng ký theo dõi một thiết bị cụ thể
    socket.on('subscribe_device', (deviceId) => {
      socket.join(`device_${deviceId}`);
      console.log(`Client ${socket.id} subscribed to device ${deviceId}`);
    });

    // Xử lý khi client hủy theo dõi một thiết bị
    socket.on('unsubscribe_device', (deviceId) => {
      socket.leave(`device_${deviceId}`);
      console.log(`Client ${socket.id} unsubscribed from device ${deviceId}`);
    });

    // Xử lý khi client ngắt kết nối
    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });
  });

  return io;
}

// Hàm gửi dữ liệu sensor mới đến các client đang theo dõi
function broadcastSensorData(deviceId, data) {
  if (io) {
    io.to(`device_${deviceId}`).emit('sensor_data', {
      device_id: deviceId,
      ...data,
      timestamp: new Date()
    });
  }
}

function broadcastEncryptedData(deviceId, data) {
  if (io) {
    io.to(`device_${deviceId}`).emit('encrypted_data', {
      device_id: deviceId,
      ...data,
      timestamp: new Date()
    });
  }
}

function broadcastDeviceStatus(deviceId, statusData) {
  if (io) {
    io.to(`device_${deviceId}`).emit('device_status', {
      device_id: deviceId,
      ...statusData,
      timestamp: new Date()
    });
  }
}

// Hàm gửi thông báo lỗi đến các client đang theo dõi
function broadcastError(deviceId, error) {
  if (io) {
    io.to(`device_${deviceId}`).emit('error', {
      device_id: deviceId,
      error: error.message,
      timestamp: new Date()
    });
  }
}

// Hàm gửi thông tin về trạng thái giải mã
function broadcastDecryptionStatus(deviceId, status) {
  if (io) {
    io.to(`device_${deviceId}`).emit('decryption_status', {
      device_id: deviceId,
      ...status,
      timestamp: new Date()
    });
  }
}

module.exports = {
  initialize,
  broadcastSensorData,
  broadcastError,
  broadcastDecryptionStatus,
  broadcastEncryptedData,
  broadcastDeviceStatus
}; 