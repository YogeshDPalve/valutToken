const crypto = require('crypto');
const { xchacha20poly1305 } = require('@noble/ciphers/chacha');
const ed25519 = require('@noble/ed25519');
const { sha512 } = require('@noble/hashes/sha512');
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
const { ulid } = require('ulid');
const { pae } = require('../utils/pae');
const {
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
  TokenInvalidError,
  AssertionMismatchError,
} = require('../utils/errors');

class TokenService {
  constructor(config) {
    this.config = config;
  }

  buildClaims(body, options = {}) {
    const iat = Math.floor(Date.now() / 1000);
    const ttl = body.ttl || this.config.token.defaultTtl;
    const exp = iat + ttl;
    const jti = ulid();

    const claims = {
      iss: this.config.token.defaultIssuer,
      sub: body.sub,
      aud: body.aud,
      iat,
      nbf: iat,
      exp,
      jti,
      typ: options.isRefresh ? 'refresh' : 'access',
      ...(body.claims || {}),
    };

    if (options.familyId) {
      claims.fid = options.familyId;
    }

    return claims;
  }

  validateClaims(claims, options = {}) {
    const now = Math.floor(Date.now() / 1000);

    if (claims.exp && now >= claims.exp) {
      throw new TokenExpiredError({ expiredAt: new Date(claims.exp * 1000).toISOString() });
    }

    if (claims.nbf && now < claims.nbf) {
      throw new TokenNotYetValidError({ validAt: new Date(claims.nbf * 1000).toISOString() });
    }

    if (claims.iss && claims.iss !== this.config.token.defaultIssuer) {
      throw new IssuerMismatchError({ expected: this.config.token.defaultIssuer, actual: claims.iss });
    }

    if (options.aud && claims.aud && claims.aud !== options.aud) {
      throw new AudienceMismatchError({ expected: options.aud, actual: claims.aud });
    }
  }

  encryptLocal(claimsObj, keyBytes, options = {}) {
    const claims = { ...claimsObj };
    if (!claims.iss) claims.iss = this.config.token.defaultIssuer; // Use config defaultIssuer
    if (!claims.exp) {
      claims.exp = Math.floor(Date.now() / 1000) + this.config.token.defaultTtl; // Use config defaultTtl
    }
    const m = Buffer.from(JSON.stringify(claims), 'utf8');
    
    // v4.local footer
    let footerBuf = Buffer.alloc(0);
    if (options.footer) {
      footerBuf = Buffer.from(typeof options.footer === 'string' ? options.footer : JSON.stringify(options.footer), 'utf8');
    }
    
    // Implicit assertion
    const iBuf = options.implicitAssertion 
      ? Buffer.from(options.implicitAssertion, 'utf8') 
      : Buffer.alloc(0);

    const nonce = crypto.randomBytes(24); // 24 bytes for xchacha20
    const header = Buffer.from('v4.local.', 'utf8');

    // PAE
    const aad = pae(header, nonce, footerBuf, iBuf);

    // @noble/ciphers requires Uint8Array inputs
    const xc = xchacha20poly1305(new Uint8Array(keyBytes), new Uint8Array(nonce), new Uint8Array(aad));
    const ciphertext = xc.encrypt(new Uint8Array(m));

    const payloadBase64 = Buffer.concat([nonce, Buffer.from(ciphertext)]).toString('base64url');
    const footerBase64 = footerBuf.toString('base64url');

    if (footerBuf.length > 0) {
      return `v4.local.${payloadBase64}.${footerBase64}`;
    }
    return `v4.local.${payloadBase64}`;
  }

  decryptLocal(token, candidateKeys, options = {}) {
    if (!token.startsWith('v4.local.')) {
      throw new TokenInvalidError('Invalid token prefix');
    }

    const parts = token.split('.');
    if (parts.length < 3) {
      throw new TokenInvalidError('Malformed token');
    }

    const payloadBuf = Buffer.from(parts[2], 'base64url');
    if (payloadBuf.length < 24 + 16) { // nonce + tag
      throw new TokenInvalidError('Token payload too short');
    }

    const nonce = payloadBuf.subarray(0, 24); 
    const ciphertext = payloadBuf.subarray(24);

    const footerBuf = parts.length === 4 ? Buffer.from(parts[3], 'base64url') : Buffer.alloc(0);
    const assertionBuf = Buffer.from(options.implicitAssertion || '', 'utf8');

    const header = Buffer.from('v4.local.', 'utf8');
    const aad = pae(header, nonce, footerBuf, assertionBuf);

    let plaintext;
    let macMatched = false;

    // Try each candidate key
    for (const keyRecord of candidateKeys) {
      if (keyRecord.purpose !== 'local') continue;
      try {
        const xc = xchacha20poly1305(new Uint8Array(keyRecord.rawKey), new Uint8Array(nonce), new Uint8Array(aad));
        plaintext = xc.decrypt(new Uint8Array(ciphertext));
        macMatched = true;
        break; // Stop at first successful decrypt
      } catch (err) {
        // MAC failed for this key, keep trying
      }
    }

    if (!macMatched) {
        // We know MAC failed. It could be wrong key, tampering, or wrong assertion.
        if (options.implicitAssertion) {
             throw new AssertionMismatchError(); // If assertion was provided, hint at that first
        }
        throw new TokenInvalidError('Invalid MAC or token tampering detected');
    }

    const claimsJson = Buffer.from(plaintext).toString('utf8');
    let claims;
    try {
      claims = JSON.parse(claimsJson);
    } catch (e) {
      throw new TokenInvalidError('Malformed claims');
    }

    this.validateClaims(claims, options);
    
    return claims;
  }

  signPublic(claims, secretKey, options = {}) {
    const claimsJson = JSON.stringify(claims);
    const m = Buffer.from(claimsJson, 'utf8');

    const footerObj = options.footer || {};
    const footerStr = typeof footerObj === 'string' ? footerObj : JSON.stringify(footerObj);
    const footerBuf = Buffer.from(footerStr, 'utf8');

    const assertionStr = options.implicitAssertion || '';
    const assertionBuf = Buffer.from(assertionStr, 'utf8');

    const header = 'v4.public.';
    const m2 = pae(header, m, footerBuf, assertionBuf);

    const sig = ed25519.sign(m2, secretKey);

    const payloadBase64 = Buffer.concat([m, Buffer.from(sig)]).toString('base64url');
    const footerBase64 = footerBuf.toString('base64url');

    return footerBase64 ? `${header}${payloadBase64}.${footerBase64}` : `${header}${payloadBase64}`;
  }

  verifyPublic(token, candidateKeys, options = {}) {
    if (!token.startsWith('v4.public.')) {
      throw new TokenInvalidError('Invalid token prefix');
    }

    const parts = token.split('.');
    if (parts.length < 3) {
      throw new TokenInvalidError('Malformed token');
    }

    const payloadBuf = Buffer.from(parts[2], 'base64url');
    if (payloadBuf.length < 64) {
      throw new TokenInvalidError('Token payload too short');
    }

    const m = payloadBuf.subarray(0, payloadBuf.length - 64);
    const sig = payloadBuf.subarray(payloadBuf.length - 64);

    const footerBuf = parts.length === 4 ? Buffer.from(parts[3], 'base64url') : Buffer.alloc(0);
    const assertionBuf = Buffer.from(options.implicitAssertion || '', 'utf8');

    const header = 'v4.public.';
    const m2 = pae(header, m, footerBuf, assertionBuf);

    let sigMatched = false;

    for (const keyRecord of candidateKeys) {
      try {
        if (ed25519.verify(sig, m2, keyRecord.publicKey)) {
            sigMatched = true;
            break;
        }
      } catch (err) {
        // Verify failed for this key
      }
    }

    if (!sigMatched) {
      if (options.implicitAssertion) {
             throw new AssertionMismatchError(); 
      }
      throw new TokenInvalidError('Invalid signature or token tampering detected');
    }

    const claimsJson = m.toString('utf8');
    let claims;
    try {
      claims = JSON.parse(claimsJson);
    } catch (e) {
      throw new TokenInvalidError('Malformed claims');
    }

    this.validateClaims(claims, options);

    return claims;
  }

  issue(claims, keyRecord, options = {}) {
      if (keyRecord.purpose === 'local') {
          return this.encryptLocal(claims, keyRecord.rawKey, options);
      } else if (keyRecord.purpose === 'public') {
          return this.signPublic(claims, keyRecord.rawKey, options);
      }
      throw new InternalError('Unknown key purpose');
  }

  verify(token, candidateKeys, options = {}) {
      const purpose = this.detectPurpose(token);
      if (purpose === 'local') {
          return this.decryptLocal(token, candidateKeys, options);
      } else if (purpose === 'public') {
          return this.verifyPublic(token, candidateKeys, options);
      }
      throw new TokenInvalidError('Unknown token purpose');
  }

  detectPurpose(token) {
    if (token.startsWith('v4.local.')) return 'local';
    if (token.startsWith('v4.public.')) return 'public';
    return null;
  }

  parseFooter(token) {
    const parts = token.split('.');
    if (parts.length === 4) {
      const footerStr = Buffer.from(parts[3], 'base64url').toString('utf8');
      try {
        return JSON.parse(footerStr);
      } catch {
        return footerStr;
      }
    }
    return null;
  }
}

module.exports = TokenService;
