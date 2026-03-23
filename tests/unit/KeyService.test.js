const ed25519 = require('@noble/ed25519');
const Redis = require('ioredis');
const crypto = require('crypto');
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
const KeyService = require('../../src/services/KeyService');

jest.mock('ioredis');

describe('KeyService', () => {
  let redis;
  let service;
  const masterSecret = crypto.randomBytes(32).toString('hex');

  beforeEach(() => {
    redis = new Redis();
    redis.set = jest.fn().mockResolvedValue('OK');
    redis.get = jest.fn().mockResolvedValue(null);
    redis.del = jest.fn().mockResolvedValue(1);
    redis.keys = jest.fn().mockResolvedValue([]);
    redis.smembers = jest.fn().mockResolvedValue([]);
    redis.sadd = jest.fn().mockResolvedValue(1);

    service = new KeyService(redis, {
      redis: { prefix: 'test:' },
      keys: { encryptionSecret: Buffer.from(masterSecret, 'hex'), rotationGracePeriod: 86400 }
    });
  });

  it('generateLocalKey returns correct ID format and encrypts material', async () => {
    const key = await service.generateLocalKey({ tenant: 'tenant-a' });
    
    expect(key.id).toMatch(/^key-v4l-[0-9A-Z]{26}$/);
    expect(key.tenant).toBe('tenant-a');
    expect(redis.set).toHaveBeenCalled();
  });

  it('generates public key returning JWKS-style structure', async () => {
    const key = await service.generatePublicKey({ tenant: 'tenant-a' });
    
    expect(key.id).toMatch(/^key-v4p-[0-9A-Z]{26}$/);
    expect(key.publicKey).toBeDefined();
    expect(redis.set).toHaveBeenCalledTimes(2); // Active key + index key
  });

  it('getActiveKey decrypts AES-256-GCM material and returns rawBuffer', async () => {
    // Generate a valid encrypted payload
    const rawKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(masterSecret, 'hex'), iv);
    
    let ciphertext = cipher.update(rawKey);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();
    const storedBase64 = Buffer.concat([iv, tag, ciphertext]).toString('base64');

    redis.get.mockResolvedValueOnce(JSON.stringify({
      id: 'key-v4l-test',
      purpose: 'local',
      key: storedBase64
    }));

    const active = await service.getActiveKey('tenant-a', 'local');
    expect(active.id).toBe('key-v4l-test');
    expect(active.purpose).toBe('local');
    expect(active.rawKey).toEqual(rawKey);
  });

  it('rotateKey generates new key and properly manages grace period', async () => {
    const { newKeyId, retiredKeyId, gracePeriodEndsAt } = await service.rotateKey('tenant-a', 'local');

    expect(newKeyId).toMatch(/^key-v4l-/);
    // Since mock get returned null, retiredKeyId is null
    expect(retiredKeyId).toBeNull(); 
    expect(new Date(gracePeriodEndsAt).getTime()).toBeGreaterThan(Date.now());
  });
});
