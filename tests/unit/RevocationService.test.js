const Redis = require('ioredis');
const RevocationService = require('../../src/services/RevocationService');

// Mock Redis
jest.mock('ioredis');

describe('RevocationService', () => {
  let redis;
  let service;

  beforeEach(() => {
    redis = new Redis();
    redis.zadd = jest.fn().mockResolvedValue(1);
    redis.sadd = jest.fn().mockResolvedValue(1);
    redis.zscore = jest.fn().mockResolvedValue(null);
    redis.sismember = jest.fn().mockResolvedValue(0);
    redis.zremrangebyscore = jest.fn().mockResolvedValue(1);
    redis.set = jest.fn().mockResolvedValue('OK');
    redis.get = jest.fn().mockResolvedValue(null);
    redis.ttl = jest.fn().mockResolvedValue(100);

    service = new RevocationService(redis, {
      redis: { prefix: 'test:' },
      token: { defaultTtl: 3600 }
    });
  });

  describe('JTI Blocklist', () => {
    it('revokes a JTI', async () => {
      await service.revoke('jti-1', 'tenant-a');
      expect(redis.zadd).toHaveBeenCalled();
    });

    it('returns false for non-revoked JTI', async () => {
      redis.zscore.mockResolvedValueOnce(null);
      const isRevoked = await service.isRevoked('jti-2', 'tenant-a');
      expect(isRevoked).toBe(false);
    });

    it('returns true for revoked JTI', async () => {
      redis.zscore.mockResolvedValueOnce('1234567890');
      const isRevoked = await service.isRevoked('jti-1', 'tenant-a');
      expect(isRevoked).toBe(true);
    });
  });

  describe('Token Families', () => {
    it('creates a family', async () => {
      const familyId = await service.createFamily('tenant-a');
      expect(familyId).toMatch(/^fam_/);
      expect(redis.set).toHaveBeenCalled();
    });

    it('registers a refresh token to an existing family', async () => {
      const familyId = 'fam_123';
      const record = { id: familyId, currentRefreshJti: null, revokedAt: null };
      redis.get.mockResolvedValueOnce(JSON.stringify(record));
      
      const res = await service.registerRefreshToken(familyId, 'jti-1', 'tenant-a');
      expect(res).toBe(true);
      expect(redis.set).toHaveBeenCalledWith(
        `test:family:tenant-a:${familyId}`,
        expect.stringContaining('"currentRefreshJti":"jti-1"'),
        'EX',
        100
      );
    });

    it('consumes a registered refresh token correctly', async () => {
       const familyId = 'fam_123';
       const record = { id: familyId, currentRefreshJti: 'jti-1', revokedAt: null };
       redis.get.mockResolvedValueOnce(JSON.stringify(record));

       const res = await service.consumeRefreshToken(familyId, 'jti-1', 'tenant-a');
       expect(res).toEqual({ valid: true, reuseDetected: false });
    });

    it('detects refresh token reuse and revokes family', async () => {
      const familyId = 'fam_123';
      // Current JTI is jti-2, but we try to consume jti-1
      const record = { id: familyId, currentRefreshJti: 'jti-2', revokedAt: null };
      redis.get.mockResolvedValueOnce(JSON.stringify(record));

      const res = await service.consumeRefreshToken(familyId, 'jti-1', 'tenant-a');
      expect(res).toEqual({ valid: false, reuseDetected: true });
      expect(redis.set).toHaveBeenCalledWith(
        `test:family:tenant-a:${familyId}`,
        expect.stringContaining('"revokedAt":'),
        'EX',
        100
      );
    });

    it('rejects consumption if family is already revoked', async () => {
      const familyId = 'fam_123';
      const record = { id: familyId, currentRefreshJti: 'jti-2', revokedAt: new Date().toISOString() };
      redis.get.mockResolvedValueOnce(JSON.stringify(record));

      const res = await service.consumeRefreshToken(familyId, 'jti-2', 'tenant-a');
      expect(res).toEqual({ valid: false, reuseDetected: true });
    });

    it('can explicitly revoke a family', async () => {
      const familyId = 'fam_123';
      const record = { id: familyId, currentRefreshJti: 'jti-1', revokedAt: null };
      redis.get.mockResolvedValueOnce(JSON.stringify(record));

      const res = await service.revokeFamily(familyId, 'tenant-a');
      expect(res).toBe(true);
      expect(redis.set).toHaveBeenCalledWith(
        `test:family:tenant-a:${familyId}`,
        expect.stringContaining('"revokedAt":'),
        'EX',
        100
      );
    });
  });
});
