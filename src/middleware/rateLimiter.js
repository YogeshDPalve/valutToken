const { RateLimitError } = require('../utils/errors');
const logger = require('../utils/logger');

function rateLimiter(redis, options = {}) {
  const limit = options.limit || 100;
  const windowSeconds = options.windowSeconds || 60;
  const prefix = options.prefix || 'vt:';
  const endpoint = options.endpoint || 'global';

  return async (req, res, next) => {
    try {
      const identifier = req.tenant || req.ip || 'unknown';
      const key = `${prefix}ratelimit:${endpoint}:${identifier}`;
      
      const now = Date.now();
      const windowStart = now - (windowSeconds * 1000);

      // Execute Redis commands in a pipeline
      const pipeline = redis.pipeline();
      pipeline.zremrangebyscore(key, '-inf', windowStart);
      pipeline.zcard(key);
      pipeline.zadd(key, now, `${now}-${Math.random()}`);
      pipeline.expire(key, windowSeconds);

      const results = await pipeline.exec();
      
      // ZCARD result is at index 1, its response is at index 1 [err, result]
      const count = results[1][1]; 

      const remaining = Math.max(0, limit - count - 1); // -1 because we just added one
      const reset = Math.ceil((now + (windowSeconds * 1000)) / 1000);

      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', remaining);
      res.setHeader('X-RateLimit-Reset', reset);

      if (count >= limit) {
        return next(new RateLimitError(windowSeconds));
      }

      next();
    } catch (err) {
      logger.error({ err, endpoint }, 'Rate limiter Redis failure, failing open');
      next();
    }
  };
}

module.exports = {
  rateLimiter
};
