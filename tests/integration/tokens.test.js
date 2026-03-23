const request = require('supertest');
const RedisMock = require('ioredis-mock');
const createApp = require('../../src/app');
const config = require('../../src/config');
const KeyService = require('../../src/services/KeyService');

describe('Tokens API Integration Tests', () => {
  let app;
  let redis;
  let keyService;

  beforeAll(async () => {
    config.auth.apiKeys.set('test-api-key-1', 'tenantA');
    config.auth.apiKeys.set('test-api-key-b', 'tenantB');
    redis = new RedisMock();
    keyService = new KeyService(redis, config);
    app = createApp(redis);
    
    await keyService.generateLocalKey({ tenant: 'tenantA' });
    await keyService.generatePublicKey({ tenant: 'tenantA' });
  });

  afterAll(async () => {
    await redis.quit();
  });

  const validApiKey = 'test-api-key-1';

  describe('POST /tokens/issue', () => {
    it('should issue a local token successfully', async () => {
      const res = await request(app)
        .post('/tokens/issue')
        .set('x-api-key', validApiKey)
        .send({
          sub: 'user123',
          purpose: 'local',
          ttl: 3600
        });

      expect(res.status).toBe(201);
      expect(res.body.token).toMatch(/^v4\.local\./);
    });

    it('should issue a public token successfully', async () => {
      const res = await request(app)
        .post('/tokens/issue')
        .set('x-api-key', validApiKey)
        .send({
          sub: 'user123',
          purpose: 'public'
        });

      expect(res.status).toBe(201);
      expect(res.body.token).toMatch(/^v4\.public\./);
    });

    it('should reject requests with invalid API key', async () => {
      const res = await request(app)
        .post('/tokens/issue')
        .set('x-api-key', 'invalid-key')
        .send({ sub: 'user123' });

      expect(res.status).toBe(401);
    });
  });

  describe('POST /tokens/verify', () => {
    let localToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/tokens/issue')
        .set('x-api-key', validApiKey)
        .send({ sub: 'user_verify' });
      localToken = res.body.token;
    });

    it('should verify a valid token', async () => {
      const res = await request(app)
        .post('/tokens/verify')
        .set('x-api-key', validApiKey)
        .send({ token: localToken });

      expect(res.status).toBe(200);
      expect(res.body.claims).toBeDefined();
      expect(res.body.claims.sub).toBe('user_verify');
    });

    it('should reject tampered token', async () => {
      const tampered = localToken.substring(0, localToken.length - 2) + 'XX';
      const res = await request(app)
        .post('/tokens/verify')
        .set('x-api-key', validApiKey)
        .send({ token: tampered });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('TOKEN_INVALID');
    });
  });

  describe('POST /tokens/revoke and introspect', () => {
    let tokenToRevoke;
    let jtiToRevoke;

    beforeAll(async () => {
      const res = await request(app)
        .post('/tokens/issue')
        .set('x-api-key', validApiKey)
        .send({ sub: 'user_revoke' });
      tokenToRevoke = res.body.token;
    });

    it('should introspect active token', async () => {
      const res = await request(app)
        .post('/tokens/introspect')
        .set('x-api-key', validApiKey)
        .send({ token: tokenToRevoke });
      expect(res.status).toBe(200);
      expect(res.body.active).toBe(true);
    });

    it('should revoke token', async () => {
      const res = await request(app)
        .post('/tokens/revoke')
        .set('x-api-key', validApiKey)
        .send({ token: tokenToRevoke });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should introspect revoked token as inactive', async () => {
      const res = await request(app)
        .post('/tokens/introspect')
        .set('x-api-key', validApiKey)
        .send({ token: tokenToRevoke });
      expect(res.status).toBe(200);
      expect(res.body.active).toBe(false);
    });

    it('should fail to verify revoked token', async () => {
      const res = await request(app)
        .post('/tokens/verify')
        .set('x-api-key', validApiKey)
        .send({ token: tokenToRevoke });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('TOKEN_INVALID');
    });
  });
});
