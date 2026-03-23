class AdminController {
  constructor(auditService, keyService, revocationService) {
    this.auditService = auditService;
    this.keyService = keyService;
    this.revocationService = revocationService;
  }

  getAuditLog = async (req, res, next) => {
    try {
      const filters = {
        tenant: req.tenant,
        event: req.query.event,
        sub: req.query.sub,
        limit: req.query.limit ? parseInt(req.query.limit, 10) : 100,
        since: req.query.since ? parseInt(req.query.since, 10) : undefined
      };
      
      const logs = await this.auditService.query(req.tenant, filters);
      res.status(200).json(logs);
    } catch (err) {
      next(err);
    }
  };

  getStats = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const stats = await this.auditService.getStats(tenant);
      const keys = await this.keyService.listKeys(tenant);
      
      res.status(200).json({
        stats,
        keys
      });
    } catch (err) {
      next(err);
    }
  };

  revokeBySubject = async (req, res, next) => {
    try {
      const { sub } = req.body;
      const tenant = req.tenant;
      
      await this.revocationService.revokeBySubject(sub, tenant);
      
      await this.auditService.log('token.revoked', { tenant, sub, method: 'subject' });
      
      res.status(200).json({ success: true, message: `All tokens for subject '${sub}' revoked` });
    } catch (err) {
      next(err);
    }
  };

  revokeFamily = async (req, res, next) => {
    try {
      const { familyId } = req.body;
      const tenant = req.tenant;
      
      await this.revocationService.revokeFamily(familyId, tenant);
      
      await this.auditService.log('token.revoked', { tenant, familyId, method: 'family' });
      
      res.status(200).json({ success: true, message: `Token family '${familyId}' revoked` });
    } catch (err) {
      next(err);
    }
  };
}

module.exports = AdminController;
