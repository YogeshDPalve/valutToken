const { ulid } = require('ulid');
const { InternalError, RefreshReuseDetectedError } = require('../utils/errors');
const logger = require('../utils/logger');

class RevocationService {
  constructor(redis, config) {
    this.redis = redis;
    this.config = config;
    this.prefix = config.redis.prefix;
  }

  /**
   * JTI Blocklist Manager
   */
  async revoke(jti, tenant, expiresAt, meta = {}) {
    const key = `${this.prefix}revoked:${tenant}`;
    // Score is expiration timestamp (ms) so we can clean up easily
    const score = expiresAt ? new Date(expiresAt).getTime() : Date.now() + this.config.token.defaultTtl * 1000;
    
    await this.redis.zadd(key, score, jti);
    
    // Optionally track by subject if provided in meta
    if (meta.sub) {
      await this.redis.sadd(`${this.prefix}revoked:sub:${tenant}:${meta.sub}`, jti);
    }
    
    // Fire and forget cleanup
    this._cleanupExpired(tenant).catch(e => logger.error(e, 'Failed to cleanup expired JTIs'));
    
    return true;
  }

  async isRevoked(jti, tenant) {
    const key = `${this.prefix}revoked:${tenant}`;
    const score = await this.redis.zscore(key, jti);
    return score !== null;
  }

  async revokeBySubject(sub, tenant) {
    // Add a sentinel value to track that the subject itself is revoked
    // For simplicity, we can just say any token issued before "now" is revoked
    const key = `${this.prefix}revoked:sub_sentinel:${tenant}`;
    await this.redis.hset(key, sub, Date.now().toString());
    return true;
  }
  
  async isSubjectRevoked(sub, tenant, iat) {
    const key = `${this.prefix}revoked:sub_sentinel:${tenant}`;
    const revokedAtStr = await this.redis.hget(key, sub);
    if (!revokedAtStr) return false;
    
    const revokedAt = parseInt(revokedAtStr, 10);
    // If token was issued before the subject was revoked, it's invalid
    return iat <= revokedAt;
  }

  async revokeByKey(keyId, tenant) {
    const key = `${this.prefix}revoked:key:${tenant}`;
    await this.redis.sadd(key, keyId);
    return true;
  }

  async isKeyRevoked(keyId, tenant) {
    const key = `${this.prefix}revoked:key:${tenant}`;
    const isMember = await this.redis.sismember(key, keyId);
    return isMember === 1;
  }

  async _cleanupExpired(tenant) {
    const key = `${this.prefix}revoked:${tenant}`;
    const now = Date.now();
    await this.redis.zremrangebyscore(key, '-inf', now - 1);
  }

  /**
   * Token Family Manager for Refresh Tokens
   */
  async createFamily(tenant) {
    const familyId = `fam_${ulid()}`;
    const key = `${this.prefix}family:${tenant}:${familyId}`;
    
    const record = {
      id: familyId,
      currentRefreshJti: null,
      revokedAt: null,
    };
    
    // TTL 30 days
    await this.redis.set(key, JSON.stringify(record), 'EX', 30 * 24 * 60 * 60);
    return familyId;
  }

  async registerRefreshToken(familyId, jti, tenant) {
    const key = `${this.prefix}family:${tenant}:${familyId}`;
    const data = await this.redis.get(key);
    
    if (!data) return false;
    
    const record = JSON.parse(data);
    record.currentRefreshJti = jti;
    
    // Keep TTL
    const ttl = await this.redis.ttl(key);
    if (ttl > 0) {
      await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
    }
    return true;
  }

  async consumeRefreshToken(familyId, jti, tenant) {
    const key = `${this.prefix}family:${tenant}:${familyId}`;
    const data = await this.redis.get(key);
    
    if (!data) {
      return { valid: false, reuseDetected: false };
    }
    
    const record = JSON.parse(data);
    
    if (record.revokedAt) {
      return { valid: false, reuseDetected: true };
    }
    
    if (jti !== record.currentRefreshJti) {
      // Reuse detected!
      record.revokedAt = new Date().toISOString();
      const ttl = await this.redis.ttl(key);
      if (ttl > 0) {
        await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
      }
      return { valid: false, reuseDetected: true };
    }
    
    // Valid consumption, clear the current JTI until a new one is registered
    record.currentRefreshJti = null;
    const ttl = await this.redis.ttl(key);
    if (ttl > 0) {
      await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
    }
    
    return { valid: true, reuseDetected: false };
  }

  async isFamilyRevoked(familyId, tenant) {
    const key = `${this.prefix}family:${tenant}:${familyId}`;
    const data = await this.redis.get(key);
    if (!data) return true; // Treating missing as revoked to be safe
    
    const record = JSON.parse(data);
    return record.revokedAt !== null;
  }

  async revokeFamily(familyId, tenant) {
    const key = `${this.prefix}family:${tenant}:${familyId}`;
    const data = await this.redis.get(key);
    if (!data) return false;
    
    const record = JSON.parse(data);
    record.revokedAt = new Date().toISOString();
    
    const ttl = await this.redis.ttl(key);
    if (ttl > 0) {
      await this.redis.set(key, JSON.stringify(record), 'EX', ttl);
    }
    return true;
  }
}

module.exports = RevocationService;
