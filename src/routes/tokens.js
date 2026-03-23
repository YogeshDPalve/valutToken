const express = require('express');
const { validate, issueSchema, verifySchema, refreshSchema, revokeSchema, introspectSchema } = require('../validators/schemas');
const { rateLimiter } = require('../middleware/rateLimiter');

function createTokenRoutes(tokenController, redis) {
  const router = express.Router();

  router.post('/issue', 
    rateLimiter(redis, { limit: 100, windowSeconds: 60, endpoint: 'issue' }),
    validate(issueSchema), 
    tokenController.issue
  );

  router.post('/verify', 
    rateLimiter(redis, { limit: 1000, windowSeconds: 60, endpoint: 'verify' }),
    validate(verifySchema), 
    tokenController.verify
  );

  router.post('/refresh', 
    rateLimiter(redis, { limit: 50, windowSeconds: 60, endpoint: 'refresh' }),
    validate(refreshSchema), 
    tokenController.refresh
  );

  router.post('/revoke', 
    rateLimiter(redis, { limit: 20, windowSeconds: 60, endpoint: 'revoke' }),
    validate(revokeSchema), 
    tokenController.revoke
  );

  router.post('/introspect', 
    rateLimiter(redis, { limit: 1000, windowSeconds: 60, endpoint: 'introspect' }),
    validate(introspectSchema), 
    tokenController.introspect
  );

  return router;
}

module.exports = createTokenRoutes;
