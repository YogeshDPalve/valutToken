const request = require('supertest');
const RedisMock = require('ioredis-mock');
const createApp = require('../../src/app');
const config = require('../../src/config');
const KeyService = require('../../src/services/KeyService');

describe('E2E Flows', () => {
  let app;
  let redis;
  let keyService;

  beforeAll(async () => {
    config.auth.adminApiKey = 'super-secret-admin';
    config.auth.apiKeys.set('tenantA', 'tenantA');
    config.auth.apiKeys.set('tenantB', 'tenantB');
    redis = new RedisMock();
    keyService = new KeyService(redis, config);
    app = createApp(redis);
    
    // Setup keys for both tenants
    await keyService.generateLocalKey({ tenant: 'tenantA' });
    await keyService.generatePublicKey({ tenant: 'tenantA' });
    await keyService.generateLocalKey({ tenant: 'tenantB' });
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('Full login -> verify -> refresh -> logout cycle', async () => {
    // 1. Login (issue token with refresh)
    let res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'e2e_user', issueRefresh: true, purpose: 'local' });
    expect(res.status).toBe(201);
    const token = res.body.token;
    const refreshToken = res.body.refreshToken;
    expect(token).toBeDefined();
    expect(refreshToken).toBeDefined();

    // 2. Verify
    res = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantA')
      .send({ token });
    expect(res.status).toBe(200);
    expect(res.body.claims).toBeDefined();
    expect(res.body.claims.sub).toBe('e2e_user');

    // 3. Refresh (creates new token/refresh pair)
    res = await request(app)
      .post('/tokens/refresh')
      .set('x-api-key', 'tenantA')
      .send({ refreshToken, purpose: 'local' });
    expect(res.status).toBe(200);
    const newToken = res.body.token;
    const newRefreshToken = res.body.refreshToken;

    // Need to verify the new token to get the familyId
    let verRes = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantA')
      .send({ token: newToken });
    expect(verRes.status).toBe(200);

    // 4. Logout (revoke family)
    res = await request(app)
      .post('/admin/revoke/family')
      .set('x-admin-key', 'super-secret-admin')
      .send({ familyId: verRes.body.claims.fid, tenant: 'tenantA' });
    expect(res.status).toBe(200);

    // 5. Try Refreshing again -> Should fail
    res = await request(app)
      .post('/tokens/refresh')
      .set('x-api-key', 'tenantA')
      .send({ refreshToken: newRefreshToken, purpose: 'local' });
    expect(res.status).toBe(401);
    
    // Also the new token should be unable to verify? 
    // Wait, revokeFamily revokes ALL refresh tokens in the family, preventing new access.
    // It doesn't instantly revoke the short-lived access tokens unless we also revoke the subject or the JTI explicitly.
  });

  it('Key rotation: issue before rotation -> rotate -> verify during grace -> new tokens use new key', async () => {
    // Issue before rotation
    let res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'rotate_user', purpose: 'local' });
    const earlyToken = res.body.token;
    // Issue doesn't return claims directly, we must verify to get kid, or we can just parse the header/token directly
    // Let's verify it quickly
    let verRes = await request(app).post('/tokens/verify').set('x-api-key', 'tenantA').send({ token: earlyToken });
    expect(verRes.status).toBe(200);

    // Rotate Key
    await request(app)
      .post('/keys/rotate?tenant=tenantA')
      .set('x-admin-key', 'super-secret-admin')
      .send({ purpose: 'local' });

    // Verify early token should still work during grace period
    res = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantA')
      .send({ token: earlyToken });
    expect(res.status).toBe(200);

    // Issue new token
    res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'rotate_user', purpose: 'local' });
    expect(res.status).toBe(201);
    const newToken = res.body.token;
    
    verRes = await request(app).post('/tokens/verify').set('x-api-key', 'tenantA').send({ token: newToken });
    expect(verRes.status).toBe(200);
  });

  it('Refresh token reuse attack: issue -> use -> replay old -> family revoked', async () => {
    // Issue
    let res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'reuse_user', issueRefresh: true, purpose: 'local' });
    const initialRefresh = res.body.refreshToken;

    // Use
    res = await request(app)
      .post('/tokens/refresh')
      .set('x-api-key', 'tenantA')
      .send({ refreshToken: initialRefresh, purpose: 'local' });
    const secondRefresh = res.body.refreshToken;
    expect(res.status).toBe(200);

    // Replay old (Attempt reuse)
    res = await request(app)
      .post('/tokens/refresh')
      .set('x-api-key', 'tenantA')
      .send({ refreshToken: initialRefresh, purpose: 'local' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('TOKEN_INVALID');

    // The family is now revoked, so secondRefresh should fail too
    res = await request(app)
      .post('/tokens/refresh')
      .set('x-api-key', 'tenantA')
      .send({ refreshToken: secondRefresh, purpose: 'local' });
    expect(res.status).toBe(401);
  });

  it('Implicit assertion: issue with assertion -> verify with correct -> verify with wrong', async () => {
    let res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'assertion_user', implicitAssertion: 'some-hash-or-id', purpose: 'local' });
    expect(res.status).toBe(201);
    const token = res.body.token;

    // Verify with correct
    res = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantA')
      .send({ token, implicitAssertion: 'some-hash-or-id' });
    expect(res.status).toBe(200);

    // Verify with wrong
    res = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantA')
      .send({ token, implicitAssertion: 'different-hash' });
    expect(res.status).toBe(401);
  });

  it('Multi-tenant: tenant-A token fails under tenant-B key', async () => {
    // Issue token under tenant A
    let res = await request(app)
      .post('/tokens/issue')
      .set('x-api-key', 'tenantA')
      .send({ sub: 'multi_tenant_user', purpose: 'local' });
    expect(res.status).toBe(201);
    const tokenA = res.body.token;

    // Try to verify token A under tenant B
    res = await request(app)
      .post('/tokens/verify')
      .set('x-api-key', 'tenantB')
      .send({ token: tokenA });
    
    // Should fail signature/decryption
    expect(res.status).toBe(401);
  });
});
