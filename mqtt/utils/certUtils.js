const crypto = require('crypto');
const cryptoUtils = require('../../crypto/chachapolyCryptoUtils/cryptoUtils');

function createSpkiPublicKey(xHex, yHex) {
    try {
        if (!xHex || !yHex || xHex.length !== 64 || yHex.length !== 64) {
            throw new Error(`Invalid public key coordinates: X=${xHex}, Y=${yHex}`);
        }
        const spkiPrefix = Buffer.from(
            '3059301306072a8648ce3d020106082a8648ce3d030107034200',
            'hex'
        );
        const rawPoint = Buffer.concat([
            Buffer.from([0x04]),
            Buffer.from(xHex, 'hex'),
            Buffer.from(yHex, 'hex')
        ]);
        return crypto.createPublicKey({
            key: Buffer.concat([spkiPrefix, rawPoint]),
            format: 'der',
            type: 'spki'
        });
    } catch (err) {
        console.error('Error creating SPKI public key:', err.message);
        throw err;
    }
}

function verifyCertificate(cleanCert) {
    try {
        return cryptoUtils.verifyCertificate(cleanCert);
    } catch (err) {
        console.error('Error verifying certificate:', err.message);
        return false;
    }
}

module.exports = { createSpkiPublicKey, verifyCertificate };