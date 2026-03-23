const express = require('express');
const { adminAuth } = require('../middleware/auth');
const { validate } = require('../validators/schemas');
const { z } = require('zod');

function createAdminRoutes(adminController, config) {
  const router = express.Router();

  // All admin routes require admin API key
  router.use(adminAuth(config));

  router.get('/audit', adminController.getAuditLog);
  router.get('/stats', adminController.getStats);

  router.post('/revoke/subject', 
    validate(z.object({ sub: z.string().min(1) })),
    adminController.revokeBySubject
  );

  router.post('/revoke/family', 
    validate(z.object({ familyId: z.string().min(1) })),
    adminController.revokeFamily
  );

  return router;
}

module.exports = createAdminRoutes;
