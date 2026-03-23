const express = require('express');
const { validate, rotateSchema } = require('../validators/schemas');
const { adminAuth } = require('../middleware/auth');
const { z } = require('zod');

function createKeyRoutes(keyController, config) {
  const router = express.Router();

  // Public endpoint for JWKS functionality
  router.get('/', keyController.getPublicKeys);

  // Admin routes
  router.post('/rotate', 
    adminAuth(config),
    validate(rotateSchema),
    keyController.rotate
  );

  router.get('/all', 
    adminAuth(config),
    keyController.list
  );

  router.post('/emergency-revoke', 
    adminAuth(config),
    validate(z.object({
      purpose: z.enum(['local', 'public']),
      keyId: z.string()
    })),
    keyController.emergencyRevoke
  );

  return router;
}

module.exports = createKeyRoutes;
