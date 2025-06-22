const { spawn } = require('child_process');
const path = require('path');
const { caCertPem } = require('../../config/config');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

async function verifyCertificate(certificate) {
  // Unchanged
  try {
    if (typeof certificate !== 'string' || !/^[0-9a-fA-F]+$/.test(certificate)) {
      console.error('Invalid certificate: must be a hexadecimal string');
      return null;
    }
    const cleanCert = certificate.replace(/[^0-9a-fA-F]/g, '');
    if (cleanCert.length !== 1040) {
      console.error(`Certificate length incorrect: expected 1040, got ${cleanCert.length}`);
      return null;
    }
    const certBytes = Buffer.from(cleanCert, 'hex');
    if (certBytes.length !== 520) {
      console.error(`Certificate bytes length incorrect: expected 520, got ${certBytes.length}`);
      return null;
    }
    const certPem = `-----BEGIN CERTIFICATE-----\n${certBytes.toString('base64')}\n-----END CERTIFICATE-----`;
    const cert = new crypto.X509Certificate(certPem);
    const ca = new crypto.X509Certificate(caCertPem);
    if (cert.issuer !== ca.subject) {
      console.error('Certificate issuer does not match CA subject');
      return null;
    }
    const now = new Date();
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    if (now < validFrom || now > validTo) {
      console.error('Certificate is not valid at current time');
      return null;
    }
    const caPublicKey = ca.publicKey;
    const isValid = cert.verify(caPublicKey);
    if (!isValid) {
      console.error('Certificate verification failed: invalid signature');
      return null;
    }
    console.log('Verifying certificate with Node.js...', { certificate: cleanCert.substring(0, 20) + '...' });
    console.log('Certificate verification result:', {
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo
    });
    return {
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.validFrom,
      validTo: cert.validTo
    };
  } catch (err) {
    console.error('Error verifying certificate:', err.message);
    return null;
  }
}

function computeSharedSecret(public_key_x, public_key_y) {
  try {
    console.log('Device public key:', { x: public_key_x, y: public_key_y });
    const serverKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const publicKey = createSpkiPublicKey(public_key_x, public_key_y);
    const sharedSecret = crypto.diffieHellman({
      publicKey,
      privateKey: serverKeyPair.privateKey
    });
    console.log('Computed shared secret:', sharedSecret.toString('hex'));
    return {
      sharedSecret,
      serverPubKeyX: serverKeyPair.publicKey.export({ type: 'spki', format: 'der' }).slice(-64, -32).toString('hex'),
      serverPubKeyY: serverKeyPair.publicKey.export({ type: 'spki', format: 'der' }).slice(-32).toString('hex')
    };
  } catch (err) {
    console.error('Error computing shared secret:', err.message);
    return null;
  }
}

async function decryptData(ciphertext, tag, nonce, sharedSecret, deviceId, message) {
  let unpadded; // Khai báo biến unpadded ở phạm vi hàm để có thể sử dụng trong catch

  try {
    console.log('Validating decryption inputs:');
    // Validate input parameters
    if (typeof ciphertext !== 'string' || !/^[0-9a-fA-F]+$/.test(ciphertext)) {
      throw new Error('Invalid ciphertext: must be a hexadecimal string');
    }
    if (typeof tag !== 'string' || !/^[0-9a-fA-F]+$/.test(tag) || tag.length !== 64) {
      throw new Error(`Invalid tag: must be a 64-character hexadecimal string, got length ${tag.length}`);
    }
    if (typeof nonce !== 'string' || !/^[0-9a-fA-F]+$/.test(nonce) || nonce.length !== 32) {
      throw new Error(`Invalid nonce: must be a 32-character hexadecimal string, got length ${nonce.length}`);
    }
    if (!(sharedSecret instanceof Buffer) || sharedSecret.length !== 32) {
      throw new Error(`Invalid shared secret: must be a 32-byte Buffer, got length ${sharedSecret.length}`);
    }

    // Determine device_id to use
    let effectiveDeviceId = deviceId;
    if (!effectiveDeviceId && message && message.device_id) {
      effectiveDeviceId = message.device_id;
      console.log(`Using device_id from message: ${effectiveDeviceId}`);
    }
    if (!effectiveDeviceId) {
      console.warn('No device_id provided; using default parsing');
    } else if (!/^[0-9a-fA-F:]+$/.test(effectiveDeviceId)) {
      console.warn(`Invalid device_id format: ${effectiveDeviceId}; proceeding with default parsing`);
      effectiveDeviceId = null;
    }

    // Convert hex strings to buffers
    const ciphertextBuf = Buffer.from(ciphertext, 'hex');
    const tagBuf = Buffer.from(tag, 'hex');
    const nonceBuf = Buffer.from(nonce, 'hex');

    console.log('Decryption inputs:', {
      ciphertextLength: ciphertextBuf.length,
      ciphertext: ciphertext.substring(0, 32) + '...',
      tag,
      nonce,
      sharedSecret: sharedSecret.toString('hex'),
      aesKey: sharedSecret.slice(0, 16).toString('hex'),
      deviceId: effectiveDeviceId || 'none'
    });

    // Validate ciphertext length
    if (ciphertextBuf.length % 16 !== 0) {
      throw new Error('Ciphertext length must be a multiple of 16 bytes');
    }

    // Verify HMAC
    console.log('Computing HMAC-SHA256...');
    const hmac = crypto.createHmac('sha256', sharedSecret);
    hmac.update(ciphertextBuf);
    const computedTag = hmac.digest();
    if (!crypto.timingSafeEqual(computedTag, tagBuf)) {
      throw new Error('HMAC verification failed: tag mismatch');
    }

    // Decrypt data
    console.log('Starting AES-128-CBC decryption...');
    const decipher = crypto.createDecipheriv('aes-128-cbc', sharedSecret.slice(0, 16), nonceBuf);
    decipher.setAutoPadding(false);
    let decryptedBuf;
    try {
      decryptedBuf = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
    } catch (err) {
      console.error('Decryption error:', err.message);
      throw err;
    }
    console.log('Decryption completed:', {
      decryptedLength: decryptedBuf.length,
      decryptedHex: decryptedBuf.toString('hex').substring(0, 64) + '...',
      decryptedTail: decryptedBuf.slice(-16).toString('hex')
    });

    // Verify PKCS7 padding
    console.log('Checking PKCS7 padding...');
    const paddingLength = decryptedBuf[decryptedBuf.length - 1];
    if (paddingLength < 1 || paddingLength > 16) {
      throw new Error(`Invalid PKCS7 padding: padding length ${paddingLength}`);
    }
    for (let i = decryptedBuf.length - paddingLength; i < decryptedBuf.length; i++) {
      if (decryptedBuf[i] !== paddingLength) {
        throw new Error('Invalid PKCS7 padding: inconsistent padding bytes');
      }
    }
    console.log('PKCS7 padding verified', { paddingLength });

    // Remove padding
    unpadded = decryptedBuf.slice(0, decryptedBuf.length - paddingLength);
    console.log('Unpadded data:', { 
      unpaddedLength: unpadded.length, 
      unpaddedText: unpadded.toString().substring(0, 100) + '...',
      unpaddedHex: unpadded.toString('hex').substring(0, 64) + '...'
    });

    // Parse JSON with deviceId replacement for corrupted data
    let parsedData;
    try {
      // First try direct parse
      parsedData = JSON.parse(unpadded.toString());
    } catch (initialError) {
      console.warn('Initial JSON parse failed, attempting to fix with deviceId replacement...');
      
      try {
        const dataStr = unpadded.toString();
        
        // Find where the actual JSON content starts (after corrupted part)
        const jsonContentStart = dataStr.indexOf('"');
        if (jsonContentStart === -1) {
          throw new Error('No valid JSON content found after corrupted section');
        }

        // Find the first comma after the JSON content starts
        const firstCommaIndex = dataStr.indexOf(',', jsonContentStart);
        if (firstCommaIndex === -1) {
          throw new Error('No comma found after device_id in JSON');
        }

        // Replace everything before the first comma with device_id from parameters
        const fixedJson = `{"device_id":"${deviceId}"${dataStr.substring(firstCommaIndex)}`;
        
        console.log('Fixed JSON:', fixedJson.substring(0, 100) + '...');
        parsedData = JSON.parse(fixedJson);
        
        console.log('Successfully recovered JSON by replacing corrupted prefix with deviceId');
      } catch (fixError) {
        console.error('Failed to fix JSON with deviceId replacement:', fixError.message);
        return { 
          status: 'error', 
          message: `Failed to parse JSON: ${fixError.message}`,
          decryptedHex: unpadded.toString('hex') 
        };
      }
    }

    // Validate the parsed data structure
    if (!parsedData || typeof parsedData !== 'object') {
      throw new Error('Decrypted data is not a valid JSON object');
    }

    // Ensure device_id is set correctly (use the provided deviceId from parameters)
    if (deviceId) {
      parsedData.device_id = deviceId;
    }

    console.log('Successfully decrypted and parsed data:', parsedData);
    return { status: 'success', data: parsedData };
    
  } catch (err) {
    console.error('Decryption error:', err.message);
    return { 
      status: 'error', 
      message: `Decryption failed: ${err.message}`,
      ...(unpadded ? { decryptedHex: unpadded.toString('hex') } : {})
    };
  }
}

function createSpkiPublicKey(xHex, yHex) {
  try {
    if (!xHex || !yHex || xHex.length !== 64 || yHex.length !== 64) {
      throw new Error(`Invalid public key coordinates: X=${xHex}, Y=${yHex}`);
    }
    const spkiPrefix = Buffer.from(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200',
      'hex'
    );
    const rawPoint = Buffer.concat([Buffer.from([0x04]), Buffer.from(xHex, 'hex'), Buffer.from(yHex, 'hex')]);
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

module.exports = {
  verifyCertificate,
  computeSharedSecret,
  decryptData,
  createSpkiPublicKey
};