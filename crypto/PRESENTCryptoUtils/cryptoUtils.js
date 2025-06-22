const { caCertPem } = require('../../config/config');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

// PRESENT Decryption Functions
function present_round(state, roundKey) {
  let result = BigInt(0);
  for (let i = 0; i < 64; i++) {
    const bit = (state[Math.floor(i / 8)] >> (i % 8)) & 0x01;
    let new_pos = i;
    if (i === 63) {
      new_pos = 63;
    } else {
      new_pos = (i * 4) % 63; // Inverse of (i * 16) % 63
    }
    result |= BigInt(bit) << BigInt(new_pos);
  }
  for (let i = 0; i < 8; i++) {
    state[i] = Number((result >> BigInt(i * 8)) & BigInt(0xFF));
  }
  const inv_sbox = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA];
  for (let i = 0; i < 8; i++) {
    state[i] = (inv_sbox[state[i] >> 4] << 4) | inv_sbox[state[i] & 0x0F];
  }
  for (let i = 0; i < 8; i++) {
    state[i] ^= roundKey[i];
  }
}

function present_key_schedule(key, roundKeys, rounds) {
  let k_high = BigInt(0);
  let k_low = BigInt(0);
  for (let i = 0; i < 8; i++) {
    k_high |= BigInt(key[i]) << BigInt(56 - i * 8);
  }
  for (let i = 8; i < 16; i++) {
    k_low |= BigInt(key[i]) << BigInt(56 - (i - 8) * 8);
  }
  const sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2];
  for (let i = 0; i < rounds; i++) {
    for (let j = 0; j < 8; j++) {
      roundKeys[i * 8 + j] = Number((k_high >> BigInt(56 - j * 8)) & BigInt(0xFF));
    }
    let temp = k_high;
    k_high = ((k_high << BigInt(61)) | (k_low >> BigInt(3))) & BigInt('0xFFFFFFFFFFFFFFFF');
    k_low = (k_low << BigInt(61)) | (temp >> BigInt(3));
    let sbox_input = Number((k_high >> BigInt(56)) & BigInt(0x0F));
    k_high = (k_high & BigInt('0x0FFFFFFFFFFFFFFF')) | (BigInt(sbox[sbox_input]) << BigInt(56));
    k_high ^= BigInt(i + 1) << BigInt(15);
  }
}

function present_decrypt(ciphertext, plaintext, key) {
  let state = Buffer.from(ciphertext);
  let roundKeys = Buffer.alloc(32 * 8);
  present_key_schedule(key, roundKeys, 32);
  for (let i = 0; i < 8; i++) {
    state[i] ^= roundKeys[31 * 8 + i];
  }
  for (let i = 30; i >= 0; i--) {
    present_round(state, roundKeys.slice(i * 8, (i + 1) * 8));
  }
  state.copy(plaintext);
}

async function verifyCertificate(certificate) {
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

async function decryptData(ciphertext, tag, iv, sharedSecret) {
  try {
    // Validate inputs
    if (typeof ciphertext !== 'string' || !/^[0-9a-fA-F]+$/.test(ciphertext)) {
      return { status: 'error', message: 'Invalid ciphertext: must be a hexadecimal string' };
    }
    if (typeof tag !== 'string' || !/^[0-9a-fA-F]+$/.test(tag) || tag.length !== 32) {
      return { status: 'error', message: `Invalid tag: must be a 32-character hexadecimal string, got length ${tag.length}` };
    }
    if (typeof iv !== 'string' || !/^[0-9a-fA-F]+$/.test(iv) || iv.length !== 16) {
      return { status: 'error', message: `Invalid IV: must be a 16-character hexadecimal string, got length ${iv.length}` };
    }
    if (!(sharedSecret instanceof Buffer) || sharedSecret.length !== 32) {
      return { status: 'error', message: `Invalid shared secret: must be a 32-byte Buffer, got length ${sharedSecret.length}` };
    }

    const ciphertextBuf = Buffer.from(ciphertext, 'hex');
    const tagBuf = Buffer.from(tag, 'hex');
    const ivBuf = Buffer.from(iv, 'hex');
    const presentKey = sharedSecret.slice(0, 16);

    // Validate ciphertext length
    if (ciphertextBuf.length % 8 !== 0) {
      return { status: 'error', message: 'Ciphertext length must be a multiple of 8 bytes for PRESENT' };
    }

    // Verify tag
    const computedTagFull = crypto.createHash('sha256').update(ciphertextBuf).digest();
    const computedTag = computedTagFull.slice(0, 16);
    if (!crypto.timingSafeEqual(computedTag, tagBuf)) {
      return { status: 'error', message: 'Tag verification failed: tag mismatch' };
    }

    // PRESENT-CBC Decryption
    let decryptedBuf = Buffer.alloc(ciphertextBuf.length);
    let prevBlock = Buffer.from(ivBuf);
    for (let i = 0; i < ciphertextBuf.length; i += 8) {
      let block = ciphertextBuf.slice(i, i + 8);
      let plaintextBlock = Buffer.alloc(8);
      present_decrypt(block, plaintextBlock, presentKey);
      for (let j = 0; j < 8; j++) {
        plaintextBlock[j] ^= prevBlock[j];
      }
      plaintextBlock.copy(decryptedBuf, i);
      prevBlock = Buffer.from(block);
    }

    // Check PKCS7 padding
    const paddingLength = decryptedBuf[decryptedBuf.length - 1];
    if (paddingLength < 1 || paddingLength > 8) {
      return { status: 'error', message: `Invalid PKCS7 padding: padding length ${paddingLength}` };
    }
    for (let i = decryptedBuf.length - paddingLength; i < decryptedBuf.length; i++) {
      if (decryptedBuf[i] !== paddingLength) {
        return { status: 'error', message: 'Invalid PKCS7 padding: inconsistent padding bytes' };
      }
    }

    // Remove padding
    const unpadded = decryptedBuf.slice(0, decryptedBuf.length - paddingLength);

    // Parse JSON
    try {
      const jsonText = unpadded.toString();
      const result = JSON.parse(jsonText);
      return { status: 'success', data: result };
    } catch (e) {
      return { 
        status: 'error', 
        message: `Failed to parse JSON: ${e.message}`, 
        decryptedText: unpadded.toString().substring(0, 100) + '...',
        decryptedHex: unpadded.toString('hex')
      };
    }
  } catch (err) {
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