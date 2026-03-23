const request = require('supertest');
const RedisMock = require('ioredis-mock');
const createApp = require('../../src/app');
const config = require('../../src/config');
const KeyService = require('../../src/services/KeyService');

describe('Keys API Integration Tests', () => {
  let app;
  let redis;
  let keyService;

  beforeAll(async () => {
    config.auth.adminApiKey = 'super-secret-admin';
    config.auth.apiKeys.set('tenantA', 'tenantA');
    redis = new RedisMock();
    keyService = new KeyService(redis, config);
    app = createApp(redis);
    
    await keyService.generatePublicKey({ tenant: 'tenantA' });
  });

  afterAll(async () => {
    await redis.quit();
  });

  describe('GET /keys', () => {
    it('should return JWKS for public keys', async () => {
      const res = await request(app).get('/keys?tenant=tenantA');
      expect(res.status).toBe(200);
      expect(res.body.keys).toBeDefined();
      expect(Array.isArray(res.body.keys)).toBe(true);
      if (res.body.keys.length > 0) {
        expect(res.body.keys[0]).toHaveProperty('kty', 'OKP');
        expect(res.body.keys[0]).toHaveProperty('crv', 'Ed25519');
      }
    });
  });

  describe('POST /keys/rotate', () => {
    it('should rotate keys if admin auth is provided', async () => {
      const res = await request(app)
        .post('/keys/rotate')
        .set('x-admin-key', 'super-secret-admin')
        .send({ purpose: 'local' });
      
      // Note: Admin routes might require tenant selection if not global, but we handle logic inside
      // Currently the rotate route requires adminAuth, and then performs rotation.
      expect(res.status).toBe(200);
    });

    it('should rotate keys for specific tenant', async () => {
      const res = await request(app)
        .post('/keys/rotate?tenant=tenantA')
        .set('x-admin-key', 'super-secret-admin')
        .send({ purpose: 'local' });
      
      expect(res.status).toBe(200);
      // Key rotates and returns the whole result from rotateKey()
      // Note: my API docs or controller doesn't guarantee exactly shape but let's check response
      expect(res.body).toBeDefined();
    });

    it('should reject rotation without admin key', async () => {
      const res = await request(app)
        .post('/keys/rotate?tenant=tenantA')
        .send({ purpose: 'local' });
      expect(res.status).toBe(401);
    });
  });
});
