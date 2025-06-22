const { spawn } = require('child_process');
const path = require('path');
const { caCertPem } = require('../../config/config');
const crypto = require('crypto');
const { createDecipheriv } = require('crypto');
const { performance } = require('perf_hooks');

// Bỏ pythonScriptPath vì không còn gọi Python nữa
// const pythonScriptPath = path.join(__dirname, '../certs/certDevice/crypto_utils.py');

// Bỏ runPythonScript vì không cần gọi Python
/*
async function runPythonScript(args) {
  return new Promise((resolve, reject) => {
    const process = spawn('python', [pythonScriptPath, ...args], { cwd: path.dirname(pythonScriptPath) });
    let stdout = '';
    let stderr = '';

    process.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    process.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    process.on('close', (code) => {
      console.log('Python script executed:', { args, code, stdout, stderr }); 
      if (code !== 0) {
        console.error(`Python script error: ${stderr}`);
        reject(new Error(`Python script exited with code ${code}: ${stderr}`));
        return;
      }
      try {
        const result = JSON.parse(stdout);
        if (result.status === 'error') {
          console.error(`Python script error: ${result.message}`);
          reject(new Error(result.message));
        } else {
          resolve(result);
        }
      } catch (err) {
        console.error(`Error parsing Python output: ${err.message}, stdout: ${stdout}`);
        reject(err);
      }
    });
  });
}
*/

async function verifyCertificate(certificate) {
  try {
    // Validate input: certificate phải là hex string, độ dài 1040 như trong Python
    if (typeof certificate !== 'string' || !/^[0-9a-fA-F]+$/.test(certificate)) {
      console.error('Invalid certificate: must be a hexadecimal string');
      return null;
    }
    const cleanCert = certificate.replace(/[^0-9a-fA-F]/g, ''); // Làm sạch giống Python
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
    const serverKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const publicKey = createSpkiPublicKey(public_key_x, public_key_y);
    const sharedSecret = crypto.diffieHellman({
      publicKey,
      privateKey: serverKeyPair.privateKey
    });
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

async function decryptData(ciphertext, tag, nonce, sharedSecret) {
  try {
    // Validate input formats
    if (typeof ciphertext !== 'string' || !/^[0-9a-fA-F]+$/.test(ciphertext)) {
      throw new Error('Invalid ciphertext: must be a hexadecimal string');
    }
    if (typeof tag !== 'string' || !/^[0-9a-fA-F]+$/.test(tag) || tag.length !== 32) {
      throw new Error(`Invalid tag: must be a 32-character hexadecimal string, got length ${tag.length}`);
    }
    if (typeof nonce !== 'string' || !/^[0-9a-fA-F]+$/.test(nonce) || nonce.length !== 24) {
      throw new Error(`Invalid nonce: must be a 24-character hexadecimal string, got length ${nonce.length}`);
    }
    if (!(sharedSecret instanceof Buffer) || sharedSecret.length !== 32) {
      throw new Error(`Invalid shared secret: must be a 32-byte Buffer, got length ${sharedSecret.length}`);
    }

    const ciphertextBuf = Buffer.from(ciphertext, 'hex');
    const tagBuf = Buffer.from(tag, 'hex');
    const nonceBuf = Buffer.from(nonce, 'hex');

    console.log('Decrypting data:', {
      ciphertextLength: ciphertextBuf.length,
      ciphertext: ciphertext.substring(0, 50) + (ciphertext.length > 50 ? '...' : ''),
      tag,
      nonce,
      sharedSecret: sharedSecret.toString('hex')
    });

    const decipher = crypto.createDecipheriv('chacha20-poly1305', sharedSecret, nonceBuf, {
      authTagLength: 16
    });
    decipher.setAuthTag(tagBuf);

    let decrypted = decipher.update(ciphertextBuf);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    try {
      // Attempt to parse as JSON
      const result = JSON.parse(decrypted.toString());
      console.log('Decrypted data (JSON):', result);
      return { status: 'success', data: result };
    } catch (e) {
      console.log('Decrypted data (non-JSON, hex):', decrypted.toString('hex'));
      return {
        status: 'error',
        message: `Failed to parse decrypted data as JSON: ${e.message}`,
        decryptedHex: decrypted.toString('hex')
      };
    }
  } catch (err) {
    console.error('Decryption error:', err.message);
    return { status: 'error', message: `Decryption failed: ${err.message}` };
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