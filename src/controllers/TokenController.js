const { TokenInvalidError, ValidationError } = require('../utils/errors');

class TokenController {
  constructor(tokenService, keyService, revocationService, auditService) {
    this.tokenService = tokenService;
    this.keyService = keyService;
    this.revocationService = revocationService;
    this.auditService = auditService;
  }

  issue = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { sub, aud, ttl, claims, purpose = 'local', issueRefresh = false } = req.body;

      // 1. Get the active key
      const keyRecord = await this.keyService.getActiveKey(tenant, purpose);

      // 2. Build explicit and implicit assertions
      const options = {
        footer: req.body.footer,
        implicitAssertion: req.body.implicitAssertion
      };
      
      let familyId;
      if (issueRefresh) {
        familyId = await this.revocationService.createFamily(tenant);
      }

      // 3. Build claims
      const tokenClaims = this.tokenService.buildClaims({ sub, aud, ttl, claims }, { familyId });

      // 4. Issue the token
      const token = this.tokenService.issue(tokenClaims, keyRecord, options);
      
      let refreshToken;
      if (issueRefresh) {
        // Build refresh token claims
        const rtClaims = this.tokenService.buildClaims({ sub, aud, ttl: 30 * 24 * 3600 }, { isRefresh: true, familyId });
        // Typically refresh tokens are always local
        const rtKeyRecord = purpose === 'local' ? keyRecord : await this.keyService.getActiveKey(tenant, 'local');
        refreshToken = this.tokenService.issue(rtClaims, rtKeyRecord, options);
        await this.revocationService.registerRefreshToken(familyId, rtClaims.jti, tenant);
      }

      await this.auditService.log('token.issued', { tenant, sub, aud, purpose, jti: tokenClaims.jti });

      const response = {
        token,
        type: 'v4.' + purpose,
        expiresAt: new Date(tokenClaims.exp * 1000).toISOString()
      };
      
      if (refreshToken) {
        response.refreshToken = refreshToken;
      }
      
      res.status(201).json(response);
    } catch (err) {
      next(err);
    }
  };

  verify = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { token, aud, implicitAssertion } = req.body;

      const purpose = this.tokenService.detectPurpose(token);
      if (!purpose) {
        throw new TokenInvalidError('Invalid token format');
      }

      const candidateKeys = await this.keyService.getCandidateKeys(tenant, purpose);
      
      const claims = this.tokenService.verify(token, candidateKeys, { aud, implicitAssertion });

      if (await this.revocationService.isRevoked(claims.jti, tenant)) {
        await this.auditService.log('token.verify_failed', { tenant, jti: claims.jti, reason: 'revoked' });
        throw new TokenInvalidError('Token is revoked');
      }

      const keyId = this.tokenService.parseFooter(token)?.kid;
      if (keyId && await this.keyService.isKeyBlocked(keyId)) {
        throw new TokenInvalidError('Token key is compromised and blocked');
      }

      await this.auditService.log('token.verified', { tenant, jti: claims.jti, sub: claims.sub });

      res.status(200).json({ claims });
    } catch (err) {
      if (err instanceof TokenInvalidError) {
        this.auditService.log('token.verify_failed', { tenant: req.tenant, reason: err.message }).catch(() => {});
      }
      next(err);
    }
  };

  refresh = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { refreshToken: token, implicitAssertion } = req.body;

      const purpose = this.tokenService.detectPurpose(token);
      if (purpose !== 'local') {
        throw new ValidationError('Refresh tokens must be v4.local');
      }

      const candidateKeys = await this.keyService.getCandidateKeys(tenant, 'local');
      const claims = this.tokenService.verify(token, candidateKeys, { implicitAssertion });

      if (claims.typ !== 'refresh') {
        throw new TokenInvalidError('Not a refresh token');
      }

      if (!claims.fid) {
        throw new TokenInvalidError('Refresh token lacks a family ID');
      }

      const { valid, reuseDetected } = await this.revocationService.consumeRefreshToken(claims.fid, claims.jti, tenant);

      if (reuseDetected) {
        await this.auditService.log('refresh.reuse_detected', { tenant, fid: claims.fid, jti: claims.jti });
        throw new TokenInvalidError('Refresh token reuse detected. Family has been revoked.');
      }

      if (!valid) {
        throw new TokenInvalidError('Refresh token family is fully revoked');
      }

      // Revoke the old refresh token JTI just in case
      await this.revocationService.revoke(claims.jti, tenant, claims.exp);

      // Issue new access and refresh token
      const keyRecord = await this.keyService.getActiveKey(tenant, 'local'); // Always use local
      const issuePurpose = req.body.purpose || 'local'; // If they want a public access token back
      const accessKeyRecord = issuePurpose === 'local' ? keyRecord : await this.keyService.getActiveKey(tenant, issuePurpose);

      const newAccessClaims = this.tokenService.buildClaims({ 
        sub: claims.sub, 
        aud: claims.aud, 
        ttl: req.body.ttl,
        claims: req.body.claims // new custom claims if passed
      }, { familyId: claims.fid });

      const newAccessToken = this.tokenService.issue(newAccessClaims, accessKeyRecord, { implicitAssertion });

      const newRefreshClaims = this.tokenService.buildClaims({ 
        sub: claims.sub, 
        aud: claims.aud, 
        ttl: 30 * 24 * 3600
      }, { isRefresh: true, familyId: claims.fid });

      const newRefreshToken = this.tokenService.issue(newRefreshClaims, keyRecord, { implicitAssertion });

      await this.revocationService.registerRefreshToken(claims.fid, newRefreshClaims.jti, tenant);
      await this.auditService.log('token.refreshed', { tenant, fid: claims.fid, sub: claims.sub });

      res.status(200).json({
        token: newAccessToken,
        type: 'v4.' + issuePurpose,
        expiresAt: new Date(newAccessClaims.exp * 1000).toISOString(),
        refreshToken: newRefreshToken
      });

    } catch (err) {
      next(err);
    }
  };

  revoke = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      let { jti, token } = req.body;

      if (!jti && token) {
        const purpose = this.tokenService.detectPurpose(token);
        const candidateKeys = await this.keyService.getCandidateKeys(tenant, purpose);
        // Do not validate audience or exp during revocation
        try {
           const claims = this.tokenService.verify(token, candidateKeys, { ignoreExpiration: true });
           jti = claims.jti;
        } catch (e) {
           throw new TokenInvalidError(`Could not decode token to find JTI for revocation: ${e.message}`);
        }
      }

      if (!jti) throw new ValidationError('Must provide jti or valid token');

      if (jti) {
        await this.revocationService.revoke(jti, tenant, Date.now() + 86400 * 1000); // Default to 24h block list
        await this.auditService.log('token.revoked', { tenant, jti, method: 'jti' });
      }

      res.status(200).json({ success: true });
    } catch (err) {
      next(err);
    }
  };

  introspect = async (req, res, next) => {
    try {
      const tenant = req.tenant;
      const { token, implicitAssertion } = req.body;

      const purpose = this.tokenService.detectPurpose(token);
      if (!purpose) {
        return res.status(200).json({ active: false });
      }

      const candidateKeys = await this.keyService.getCandidateKeys(tenant, purpose);
      
      let claims;
      try {
        claims = this.tokenService.verify(token, candidateKeys, { implicitAssertion });
      } catch {
        return res.status(200).json({ active: false });
      }

      if (await this.revocationService.isRevoked(claims.jti, tenant)) {
        return res.status(200).json({ active: false });
      }

      const keyId = this.tokenService.parseFooter(token)?.kid;
      if (keyId && await this.keyService.isKeyBlocked(keyId)) {
        return res.status(200).json({ active: false });
      }

      res.status(200).json({ active: true, claims });
    } catch (err) {
      // Introspect never throws standard errors unless internal
      next(err);
    }
  };
}

module.exports = TokenController;
