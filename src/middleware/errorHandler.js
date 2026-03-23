const { VaultTokenError } = require('../utils/errors');
const { ZodError } = require('zod');
const logger = require('../utils/logger');

function errorHandler(err, req, res, next) {
  if (err instanceof VaultTokenError) {
    const response = {
      error: err.code,
      message: err.message,
    };
    
    if (err.details && Object.keys(err.details).length > 0) {
      Object.assign(response, err.details);
    }
    
    return res.status(err.statusCode).json(response);
  }

  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'VALIDATION_ERROR',
      message: 'Input validation failed',
      details: err.flatten().fieldErrors
    });
  }

  // SyntaxError usually comes from express.json() when body is malformed JSON
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: 'BAD_REQUEST',
      message: 'Malformed JSON payload'
    });
  }

  // Log unknown errors but don't leak stack traces
  logger.error({ err, path: req.path }, 'Unhandled exception in request');

  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message: 'An unexpected internal error occurred'
  });
}

module.exports = errorHandler;
