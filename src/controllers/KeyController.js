class KeyController {
  constructor(keyService, auditService) {
    this.keyService = keyService;
    this.auditService = auditService;
  }

  getPublicKeys = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const keys = await this.keyService.getPublicKeys(tenant);
      res.status(200).json({ keys });
    } catch (err) {
      next(err);
    }
  };

  rotate = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { purpose, gracePeriod } = req.body;
      
      const result = await this.keyService.rotateKey(tenant, purpose, gracePeriod);
      
      await this.auditService.log('key.rotated', { 
        tenant, 
        purpose, 
        newKeyId: result.newKeyId, 
        retiredKeyId: result.retiredKeyId 
      });
      
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  list = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const result = await this.keyService.listKeys(tenant);
      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  };

  emergencyRevoke = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { purpose, keyId } = req.body;
      
      await this.keyService.emergencyRevokeKey(tenant, purpose, keyId);
      
      await this.auditService.log('key.emergency_revoked', { tenant, purpose, keyId });
      
      res.status(200).json({ success: true, message: `Key ${keyId} revoked and blocked` });
    } catch (err) {
      next(err);
    }
  };
}

module.exports = KeyController;
