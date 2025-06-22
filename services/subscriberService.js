const mqttClient = require('../mqtt/mqttClient');

// State management
const subscribedDevices = new Set();
const messageHandlers = new Map();

async function subscribeDevice(deviceId) {
    if (subscribedDevices.has(deviceId)) {
        return {
            success: true,
            message: `Already subscribed to device ${deviceId}`
        };
    }

    const topic = `device/${deviceId}/message`;
    
    return new Promise((resolve) => {
        mqttClient.subscribe(topic, (err) => {
            if (err) {
                resolve({
                    success: false,
                    error: err.message
                });
            } else {
                subscribedDevices.add(deviceId);
                resolve({
                    success: true,
                    message: `Successfully subscribed to device ${deviceId}`
                });
            }
        });
    });
}

async function unsubscribeDevice(deviceId) {
    if (!subscribedDevices.has(deviceId)) {
        return {
            success: true,
            message: `Not subscribed to device ${deviceId}`
        };
    }

    const topic = `device/${deviceId}/message`;
    
    return new Promise((resolve) => {
        mqttClient.unsubscribe(topic, (err) => {
            if (err) {
                resolve({
                    success: false,
                    error: err.message
                });
            } else {
                subscribedDevices.delete(deviceId);
                messageHandlers.delete(deviceId);
                resolve({
                    success: true,
                    message: `Successfully unsubscribed from device ${deviceId}`
                });
            }
        });
    });
}

function registerMessageHandler(deviceId, handler) {
    if (!subscribedDevices.has(deviceId)) {
        throw new Error(`Not subscribed to device ${deviceId}`);
    }
    messageHandlers.set(deviceId, handler);
}

function removeMessageHandler(deviceId) {
    messageHandlers.delete(deviceId);
}

function getSubscribedDevices() {
    return Array.from(subscribedDevices);
}

module.exports = {
    subscribeDevice,
    unsubscribeDevice,
    registerMessageHandler,
    removeMessageHandler,
    getSubscribedDevices
}; 