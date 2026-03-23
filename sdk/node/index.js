const axios = require('axios');

/**
 * VaultToken Client SDK
 * 
 * Provides a familiar API for managing PASETO tokens via the VaultToken server.
 */
class VaultClient {
  /**
   * @param {Object} options
   * @param {string} options.baseUrl - The URL of the VaultToken server (e.g., http://localhost:3000)
   * @param {string} options.apiKey - Your tenant-specific API key
   */
  constructor({ baseUrl, apiKey }) {
    if (!baseUrl || !apiKey) {
      throw new Error('VaultClient requires baseUrl and apiKey');
    }

    this.client = axios.create({
      baseURL: baseUrl.replace(/\/$/, ''), // Remove trailing slash
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Equivalent to jwt.sign()
   * Issues a new PASETO token (local or public).
   * 
   * @param {Object} claims - Payload to include (sub, aud, etc.)
   * @param {Object} options - Extension options (ttl, purpose, issueRefresh, etc.)
   * @returns {Promise<{token: string, refreshToken?: string}>}
   */
  async sign(claims, options = {}) {
    try {
      const response = await this.client.post('/tokens/issue', {
        ...claims,
        ...options
      });
      return response.data;
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Equivalent to jwt.verify()
   * Verifies a token's integrity and validity.
   * 
   * @param {string} token - The PASETO token string
   * @param {string} [implicitAssertion] - Optional IP/UA binding check
   * @returns {Promise<Object>} The verified claims
   */
  async verify(token, implicitAssertion = null) {
    try {
      const response = await this.client.post('/tokens/verify', {
        token,
        implicitAssertion
      });
      return response.data.claims;
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Equivalent to jwt.decode()
   * Introspects the token without throwing on invalid/revoked status.
   * 
   * @param {string} token 
   * @returns {Promise<{active: boolean, claims?: Object}>}
   */
  async decode(token) {
    try {
      const response = await this.client.post('/tokens/introspect', { token });
      return response.data;
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Refresh an expired token using a refresh token.
   * 
   * @param {string} refreshToken 
   * @returns {Promise<{token: string, refreshToken: string}>}
   */
  async refresh(refreshToken) {
    try {
      const response = await this.client.post('/tokens/refresh', { refreshToken });
      return response.data;
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Explicitly revoke a token or its JTI.
   * 
   * @param {Object} identifier - { jti } or { token }
   */
  async revoke(identifier) {
    try {
      await this.client.post('/tokens/revoke', identifier);
      return { success: true };
    } catch (err) {
      this._handleError(err);
    }
  }

  _handleError(err) {
    const message = err.response?.data?.error || err.response?.data?.message || err.message;
    const status = err.response?.status;
    
    const error = new Error(message);
    error.status = status;
    error.code = err.response?.data?.error || 'SDK_ERROR';
    
    throw error;
  }
}

module.exports = VaultClient;
