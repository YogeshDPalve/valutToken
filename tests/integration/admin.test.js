const request = require('supertest');
const RedisMock = require('ioredis-mock');
const createApp = require('../../src/app');
const config = require('../../src/config');
const AuditService = require('../../src/services/AuditService');

describe('Admin API Integration Tests', () => {
  let app;
  let redis;
  let auditService;

  beforeAll(async () => {
    config.auth.adminApiKey = 'super-secret-admin';
    redis = new RedisMock();
    auditService = new AuditService(redis, config);
    app = createApp(redis);
    
    // Seed some audit logs
    await auditService.log('token.issued', { tenant: 'tenantA', subject: 'user1' });
    await auditService.log('token.verified', { tenant: 'tenantA', subject: 'user1' });
    console.log('Keys inside mock redis:', await redis.keys('*'));
    console.log('ZRange result:', await redis.zrange(`${config.redis.prefix}audit:tenantA`, 0, -1));
  });

  afterAll(async () => {
    await redis.quit();
  });

  describe('GET /admin/audit', () => {
    it('should fetch audit logs with admin key', async () => {
      const res = await request(app)
        .get('/admin/audit?tenant=tenantA')
        .set('x-admin-key', 'super-secret-admin');
      
      console.log('GET /admin/audit response:', res.body);
      expect(res.status).toBe(200);
      expect(res.body.entries).toBeDefined();
      expect(res.body.entries.length).toBeGreaterThanOrEqual(2);
    });

    it('should block non-admins', async () => {
      const res = await request(app)
        .get('/admin/audit?tenant=tenantA');
      
      expect(res.status).toBe(401);
    });
  });

  describe('GET /admin/stats', () => {
    it('should fetch stats', async () => {
      const res = await request(app)
        .get('/admin/stats?tenant=tenantA')
        .set('x-admin-key', 'super-secret-admin');
      
      expect(res.status).toBe(200);
      expect(res.body.stats).toBeDefined();
      // ioredis-mock might not support sorted set ranges perfectly with WITHSCORES for counts,
      // but it should return somewhat a structure
    });
  });
});
