const crypto = require('crypto');
const { UnauthorizedError } = require('../utils/errors');

function auth(config) {
  return (req, res, next) => {
    const apiKeyHeader = req.header('X-Api-Key');
    
    if (!apiKeyHeader) {
      return next(new UnauthorizedError('Missing X-Api-Key header'));
    }

    const providedBuf = Buffer.from(apiKeyHeader, 'utf8');

    for (const [validKey, tenantId] of config.auth.apiKeys.entries()) {
      const validBuf = Buffer.from(validKey, 'utf8');
      
      if (providedBuf.length === validBuf.length && crypto.timingSafeEqual(providedBuf, validBuf)) {
        req.tenant = tenantId;
        return next();
      }
    }

    return next(new UnauthorizedError('Invalid API key'));
  };
}

function adminAuth(config) {
  return (req, res, next) => {
    const adminKeyHeader = req.header('X-Admin-Key');
    
    if (!adminKeyHeader) {
      return next(new UnauthorizedError('Missing X-Admin-Key header'));
    }

    const providedBuf = Buffer.from(adminKeyHeader, 'utf8');
    const validBuf = Buffer.from(config.auth.adminApiKey, 'utf8');

    if (providedBuf.length === validBuf.length && crypto.timingSafeEqual(providedBuf, validBuf)) {
      req.isAdmin = true;
      req.tenant = req.query.tenant || (req.body && req.body.tenant) || 'system';
      return next();
    }

    return next(new UnauthorizedError('Invalid Admin key'));
  };
}

module.exports = {
  auth,
  adminAuth
};
