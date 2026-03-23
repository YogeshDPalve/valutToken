const crypto = require('crypto');
const ed25519 = require('@noble/ed25519');
const { sha512 } = require('@noble/hashes/sha512');
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
const TokenService = require('../../src/services/TokenService');
const {
  TokenExpiredError,
  TokenInvalidError,
  AudienceMismatchError,
  AssertionMismatchError
} = require('../../src/utils/errors');

describe('TokenService', () => {
  let service;
  const config = {
    token: { defaultTtl: 3600, defaultIssuer: 'vaulttoken' }
  };

  beforeEach(() => {
    service = new TokenService(config);
  });

  describe('v4.local (Encryption)', () => {
    const key = crypto.randomBytes(32);
    const keyRecord = { rawKey: key, purpose: 'local' };

    it('round trips encrypt and decrypt successfully', () => {
      const claims = service.buildClaims({ sub: 'user_1', aud: 'api.test' });
      const token = service.encryptLocal(claims, key, { implicitAssertion: 'ip:1.1.1.1' });
      
      const decrypted = service.decryptLocal(token, [keyRecord], { implicitAssertion: 'ip:1.1.1.1' });
      
      expect(decrypted.sub).toBe('user_1');
      expect(decrypted.aud).toBe('api.test');
      expect(decrypted.iss).toBe('vaulttoken');
    });

    it('throws TokenInvalidError on wrong key', () => {
      const claims = service.buildClaims({ sub: 'user_1' });
      const token = service.encryptLocal(claims, key);
      
      const wrongKey = crypto.randomBytes(32);
      expect(() => {
        service.decryptLocal(token, [{ rawKey: wrongKey }], {});
      }).toThrow(TokenInvalidError);
    });

    it('throws AssertionMismatchError on wrong implicit assertion', () => {
      const claims = service.buildClaims({ sub: 'user_1' });
      const token = service.encryptLocal(claims, key, { implicitAssertion: 'ip:1.1.1.1' });
      
      expect(() => {
        service.decryptLocal(token, [keyRecord], { implicitAssertion: 'ip:2.2.2.2' });
      }).toThrow(AssertionMismatchError);
    });

    it('throws TokenExpiredError when expired', () => {
      const claims = service.buildClaims({ sub: 'user_1' });
      claims.exp = Math.floor(Date.now() / 1000) - 100; // Expired
      const token = service.encryptLocal(claims, key);
      
      expect(() => {
        service.decryptLocal(token, [keyRecord]);
      }).toThrow(TokenExpiredError);
    });

    it('throws AudienceMismatchError when audience does not match', () => {
      const claims = service.buildClaims({ sub: 'user_1', aud: 'api.test' });
      const token = service.encryptLocal(claims, key);
      
      expect(() => {
        service.decryptLocal(token, [keyRecord], { aud: 'api.wrong' });
      }).toThrow(AudienceMismatchError);
    });
  });

  describe('v4.public (Signatures)', () => {
    const secretKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(secretKey);
    const keyRecord = { rawKey: secretKey, publicKey: publicKey, purpose: 'public' };

    it('round trips sign and verify successfully', () => {
      const claims = service.buildClaims({ sub: 'user_2', aud: 'api.public' });
      const token = service.signPublic(claims, secretKey, { footer: { kid: '123' }});
      
      const verified = service.verifyPublic(token, [keyRecord]);
      expect(verified.sub).toBe('user_2');
    });

    it('throws TokenInvalidError on tampered signature', () => {
        const claims = service.buildClaims({ sub: 'user_2' });
        const token = service.signPublic(claims, secretKey);
        
        // Tamper with the last character (which is part of the signature in base64url)
        let parts = token.split('.');
        let payload = parts[2];
        let lastChar = payload[payload.length - 1];
        let newChar = lastChar === 'a' ? 'b' : 'a';
        parts[2] = payload.substring(0, payload.length - 1) + newChar;
        const tamperedToken = parts.join('.');

        expect(() => {
            service.verifyPublic(tamperedToken, [keyRecord]);
        }).toThrow(TokenInvalidError);
    });
  });
});
