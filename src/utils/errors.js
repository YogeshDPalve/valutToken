class VaultTokenError extends Error {
  constructor(message, code, statusCode, details = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends VaultTokenError {
  constructor(details) {
    super('Validation Error', 'VALIDATION_ERROR', 400, details);
  }
}

class UnauthorizedError extends VaultTokenError {
  constructor(message = 'Unauthorized') {
    super(message, 'UNAUTHORIZED', 401);
  }
}

class TokenInvalidError extends VaultTokenError {
  constructor(message = 'Invalid token') {
    super(message, 'TOKEN_INVALID', 401);
  }
}

class TokenExpiredError extends VaultTokenError {
  constructor(details) {
    super('Token has expired', 'TOKEN_EXPIRED', 401, details);
  }
}

class TokenNotYetValidError extends VaultTokenError {
  constructor(details) {
    super('Token is not yet valid', 'TOKEN_NOT_YET_VALID', 401, details);
  }
}

class TokenRevokedError extends VaultTokenError {
  constructor(details) {
    super('Token has been revoked', 'TOKEN_REVOKED', 401, details);
  }
}

class AudienceMismatchError extends VaultTokenError {
  constructor(details) {
    super('Audience mismatch', 'AUDIENCE_MISMATCH', 401, details);
  }
}

class IssuerMismatchError extends VaultTokenError {
  constructor(details) {
    super('Issuer mismatch', 'ISSUER_MISMATCH', 401, details);
  }
}

class AssertionMismatchError extends VaultTokenError {
  constructor(details) {
    super('Implicit assertion mismatch', 'ASSERTION_MISMATCH', 401, details);
  }
}

class RefreshReuseDetectedError extends VaultTokenError {
  constructor(details) {
    super('Refresh token already used — possible token theft. Family revoked.', 'REFRESH_REUSE_DETECTED', 401, details);
  }
}

class RateLimitError extends VaultTokenError {
  constructor(retryAfter) {
    super('Rate limit exceeded', 'RATE_LIMITED', 429, { retryAfter });
  }
}

class NoActiveKeyError extends VaultTokenError {
  constructor(purpose) {
    super(`No active key found for purpose: ${purpose}`, 'NO_ACTIVE_KEY', 500);
  }
}

class InternalError extends VaultTokenError {
  constructor(message = 'Internal server error') {
    super(message, 'INTERNAL_ERROR', 500);
  }
}

class KeyDecryptionError extends InternalError {
  constructor() {
    super('Failed to decrypt key material at rest');
  }
}

module.exports = {
  VaultTokenError,
  ValidationError,
  UnauthorizedError,
  TokenInvalidError,
  TokenExpiredError,
  TokenNotYetValidError,
  TokenRevokedError,
  AudienceMismatchError,
  IssuerMismatchError,
  AssertionMismatchError,
  RefreshReuseDetectedError,
  RateLimitError,
  NoActiveKeyError,
  InternalError,
  KeyDecryptionError,
};
