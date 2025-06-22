const winston = require('winston');
const path = require('path');
const fs = require('fs');

const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

const mqttLogger = winston.createLogger({
  format: logFormat,
  transports: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'mqtt.log'),
      level: 'info'
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'mqtt-error.log'),
      level: 'error'
    })
  ]
});

const systemLogger = winston.createLogger({
  format: logFormat,
  transports: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'system.log'),
      level: 'info'
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'system-error.log'),
      level: 'error'
    })
  ]
});

const errorLogger = winston.createLogger({
  format: logFormat,
  transports: [
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'),
      level: 'error'
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  mqttLogger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
  
  systemLogger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
  
  errorLogger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Helper functions
const logMqtt = {
  info: (message, meta = {}) => {
    mqttLogger.info(message, { ...meta, category: 'mqtt' });
  },
  error: (message, meta = {}) => {
    mqttLogger.error(message, { ...meta, category: 'mqtt' });
    errorLogger.error(message, { ...meta, category: 'mqtt' });
  },
  warn: (message, meta = {}) => {
    mqttLogger.warn(message, { ...meta, category: 'mqtt' });
  },
  debug: (message, meta = {}) => {
    mqttLogger.debug(message, { ...meta, category: 'mqtt' });
  }
};

const logSystem = {
  info: (message, meta = {}) => {
    systemLogger.info(message, { ...meta, category: 'system' });
  },
  error: (message, meta = {}) => {
    systemLogger.error(message, { ...meta, category: 'system' });
    errorLogger.error(message, { ...meta, category: 'system' });
  },
  warn: (message, meta = {}) => {
    systemLogger.warn(message, { ...meta, category: 'system' });
  },
  debug: (message, meta = {}) => {
    systemLogger.debug(message, { ...meta, category: 'system' });
  }
};

const logError = {
  error: (message, meta = {}) => {
    errorLogger.error(message, { ...meta, category: 'error' });
  }
};

module.exports = {
  logMqtt,
  logSystem,
  logError
};