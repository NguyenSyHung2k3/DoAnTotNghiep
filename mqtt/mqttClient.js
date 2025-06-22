const mqtt = require('mqtt');
const { mqttConfig } = require('../config/config');
const { logMqtt, logError } = require('../utils/logger');

let client = null;
const subscribedTopics = new Set();
const messageHandlers = [];
let isConnecting = false;

function initializeMqttClient() {
    if (client && client.connected) {
        logMqtt.info('MQTT client already connected');
        return client;
    }

    client = mqtt.connect({
        ...mqttConfig,
        clientId: `server_${Math.random().toString(16).slice(3)}`,
        keepalive: 60,
        reconnectPeriod: 5000,
        connectTimeout: 30000,
        clean: true
    });

    client.on('connect', () => {
        logMqtt.info('Connected to MQTT broker');
        // Subscribe to static topics
    });

    client.on('message', (topic, message) => {
        logMqtt.info(`Raw message received on topic ${topic}:`);
        messageHandlers.forEach((callback) => callback(topic, message));
    });

    client.on('error', (err) => {
        logError.error('MQTT error:', err.message);
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
            logMqtt.info('Connection failed, relying on automatic reconnection...');
        }
    });

    client.on('close', () => {
        logMqtt.info('MQTT connection closed');
        subscribedTopics.clear();
    });

    client.on('reconnect', () => {
        logMqtt.info('Attempting to reconnect to MQTT broker...');
    });

    client.on('offline', () => {
        logMqtt.info('MQTT client offline');
    });

    return client;
}

function subscribeToDeviceTopics(deviceIds) {
    deviceIds.forEach((deviceId) => {
        const topics = [
            `iot/${deviceId}/device_key`,
            `iot/${deviceId}/sensors`,
            `iot/${deviceId}/renew_cert`,
            `iot/${deviceId}/cert_confirmation`,
            `iot/${deviceId}/revoke_confirmation`,
        ];
        topics.forEach((topic) => {
            if (subscribedTopics.has(topic)) {
                logMqtt.info(`Already subscribed to ${topic}, skipping`);
                return;
            }
            client.subscribe(topic, { qos: 1 }, (err) => {
                if (err) {
                    logError.error(`Failed to subscribe to ${topic}:`, err.message);
                } else {
                    logMqtt.info(`Subscribed to ${topic}`);
                    subscribedTopics.add(topic);
                }
            });
        });
    });
}

function subscribe(topic, callback) {
    if (!client) {
        logMqtt.info(`MQTT client not initialized, initializing for ${topic}`);
        initializeMqttClient();
        return;
    }
    if (!client.connected) {
        logMqtt.info(`MQTT client not connected, waiting for connection for ${topic}`);
        return;
    }
    if (subscribedTopics.has(topic)) {
        logMqtt.info(`Already subscribed to ${topic}, skipping`);
        if (callback) callback(null);
        return;
    }
    client.subscribe(topic, { qos: 1 }, (err) => {
        if (err) {
            logError.error(`Failed to subscribe to ${topic}:`, err.message);
        } else {
            logMqtt.info(`Subscribed to ${topic}`);
            subscribedTopics.add(topic);
        }
        if (callback) callback(err);
    });
}

function publish(topic, message, optionsOrCallback, callback) {
    if (!client || !client.connected) {
        logError.error(`Cannot publish to ${topic}: MQTT client not connected`);
        const error = new Error('MQTT client not connected');
        if (typeof optionsOrCallback === 'function') {
            optionsOrCallback(error);
        } else if (callback) {
            callback(error);
        }
        return;
    }

    let options = { qos: 1 };
    let cb = null;

    if (typeof optionsOrCallback === 'function') {
        cb = optionsOrCallback;
    } else if (optionsOrCallback && typeof optionsOrCallback === 'object') {
        options = { ...options, ...optionsOrCallback };
        cb = callback;
    }

    client.publish(topic, message, options, (err) => {
        if (err) {
            logError.error(`Failed to publish to ${topic}:`, err.message);
            if (cb) cb(err);
        } else {
            logMqtt.info(`Published to ${topic}`);
            if (cb) cb(null);
        }
    });
}

function onMessage(callback) {
    if (!client) {
        logMqtt.info('MQTT client not initialized, queuing message handler');
        messageHandlers.push(callback);
        initializeMqttClient();
        return;
    }
    if (!client.connected) {
        logMqtt.info('MQTT client not connected, queuing message handler');
        messageHandlers.push(callback);
        return;
    }
    if (!messageHandlers.includes(callback)) {
        messageHandlers.push(callback);
        logMqtt.info('Registered message handler');
    }
}

function publishMessage(topic, message) {
    return new Promise((resolve, reject) => {
        if (!client || !client.connected) {
            logError.error(`Cannot publish to ${topic}: MQTT client not connected`);
            return resolve({
                success: false,
                error: 'MQTT client not connected'
            });
        }

        const messageString = JSON.stringify(message);
        client.publish(topic, messageString, { qos: 1 }, (err) => {
            if (err) {
                logError.error(`Failed to publish to ${topic}:`, err.message);
                resolve({
                    success: false,
                    error: err.message
                });
            } else {
                logMqtt.info(`Published to ${topic}:`, messageString);
                resolve({
                    success: true
                });
            }
        });
    });
}

const connectMQTT = async () => {
    if (isConnecting) {
        return;
    }

    isConnecting = true;
    
    try {
        if (client) {
            client.end();
            client = null;
        }

        client = initializeMqttClient();
        isConnecting = false;
        return client;
    } catch (error) {
        logError.error('Error connecting to MQTT broker', {
            error: error.message
        });
        isConnecting = false;
        throw error;
    }
};

const restartMQTTConnection = async () => {
    try {
        await connectMQTT();
        logMqtt.info('MQTT connection restarted successfully');
    } catch (error) {
        logError.error('Failed to restart MQTT connection', {
            error: error.message
        });
        throw error;
    }
};

module.exports = {
    initializeMqttClient,
    subscribe,
    subscribeToDeviceTopics,
    publish,
    publishMessage,
    onMessage,
    restartMQTTConnection
};