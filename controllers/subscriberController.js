const subscriberService = require('../services/subscriberService');

const subscribeDevice = async (req, res) => {
    try {
        const { deviceId } = req.body;

        if (!deviceId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: deviceId'
            });
        }

        const result = await subscriberService.subscribeDevice(deviceId);

        if (result.success) {
            return res.status(200).json(result);
        } else {
            return res.status(500).json(result);
        }
    } catch (error) {
        console.error('Error in subscribeDevice:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
};

const unsubscribeDevice = async (req, res) => {
    try {
        const { deviceId } = req.body;

        if (!deviceId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: deviceId'
            });
        }

        const result = await subscriberService.unsubscribeDevice(deviceId);

        if (result.success) {
            return res.status(200).json(result);
        } else {
            return res.status(500).json(result);
        }
    } catch (error) {
        console.error('Error in unsubscribeDevice:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
};

const getSubscribedDevices = async (req, res) => {
    try {
        const devices = subscriberService.getSubscribedDevices();
        return res.status(200).json({
            success: true,
            data: devices
        });
    } catch (error) {
        console.error('Error in getSubscribedDevices:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
};

module.exports = {
    subscribeDevice,
    unsubscribeDevice,
    getSubscribedDevices
};