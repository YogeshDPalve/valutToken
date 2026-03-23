const logger = require('../utils/logger');
const { InternalError } = require('../utils/errors');
const fs = require('fs');

const EVENTS = {
  TOKEN_ISSUED: 'token.issued',
  TOKEN_VERIFIED: 'token.verified',
  TOKEN_VERIFY_FAILED: 'token.verify_failed',
  TOKEN_REVOKED: 'token.revoked',
  TOKEN_REFRESHED: 'token.refreshed',
  REFRESH_REUSE_DETECTED: 'refresh.reuse_detected',
  KEY_GENERATED: 'key.generated',
  KEY_ROTATED: 'key.rotated',
  KEY_RETIRED: 'key.retired',
  KEY_EMERGENCY_REVOKED: 'key.emergency_revoked',
};

class AuditService {
  constructor(redis, config) {
    this.redis = redis;
    this.config = config;
    this.events = EVENTS;
    this.maxEntries = 10000; // Limit entries per tenant
  }

  /**
   * Log an audit event
   */
  async log(event, data = {}) {
    const tenant = data.tenant || 'system';
    const ts = Date.now();

    // Sanitize sensitive info just in case
    const sanitizedInput = { ...data };
    delete sanitizedInput.rawKey;
    delete sanitizedInput.secretKey;
    delete sanitizedInput.token;
    delete sanitizedInput.refreshToken;
    delete sanitizedInput.key;

    const entry = {
      ts: new Date(ts).toISOString(),
      event,
      ...sanitizedInput,
    };

    // Emit to Pino logger
    logger.info({ audit: true, ...entry }, `Audit: ${event}`);

    try {
      // 1. Add to sorted set (score = timestamp)
      // 2. Increment stats
      // 3. Trim sorted set
      const pipeline = this.redis.pipeline();
      pipeline.zadd(`${this.config.redis.prefix}audit:${tenant}`, ts, JSON.stringify(entry));
      pipeline.hincrby(`${this.config.redis.prefix}stats:${tenant}`, event, 1);
      await pipeline.exec();
    } catch (err) {
      logger.error({ err, event }, 'Failed to persist audit log to Redis');
      // We don't throw - audit logging should not fail the main request
    }
  }

  /**
   * Query the audit log
   */
  async query(tenant, filters = {}) {
    try {
      const {
        since = Date.now() - 24 * 60 * 60 * 1000,
        event,
        sub,
        limit = 50,
      } = filters;

      const keyToSearch = `${this.config.redis.prefix}audit:${tenant}`;
      const results = await this.redis.zrevrange(
        keyToSearch,
        0,
        -1
      );
      let entries = results.map((r) => JSON.parse(r));

      // In-memory filters
      if (event) {
        entries = entries.filter((e) => e.event === event);
      }
      if (sub) {
        entries = entries.filter((e) => e.sub === sub);
      }

      entries = entries.slice(0, Number(limit));

      return {
        entries,
        total: entries.length,
      };
    } catch (err) {
      throw new InternalError('Failed to query audit log');
    }
  }

  /**
   * Get aggregate stats
   */
  async getStats(tenant) {
    try {
      const pipeline = this.redis.pipeline();
      pipeline.hgetall(`${this.config.redis.prefix}stats:${tenant}`);
      pipeline.zcard(`${this.config.redis.prefix}revoked:${tenant}`);
      
      const results = await pipeline.exec();
      const hgetallRes = results[0][1] || {};
      const revokedCount = results[1][1] || 0;

      // Ensure consistent returning of specific known stats
      return {
        issued: { total: Number(hgetallRes[EVENTS.TOKEN_ISSUED] || 0) },
        verified: { total: Number(hgetallRes[EVENTS.TOKEN_VERIFIED] || 0) },
        revoked: { total: revokedCount }, // Real-time count from active list
        failed: { total: Number(hgetallRes[EVENTS.TOKEN_VERIFY_FAILED] || 0) },
        refreshed: { total: Number(hgetallRes[EVENTS.TOKEN_REFRESHED] || 0) },
      };
    } catch (err) {
      throw new InternalError('Failed to get stats');
    }
  }
}

module.exports = AuditService;
