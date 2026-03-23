const pino = require('pino');
const config = require('../config');

// Ensure we don't log sensitive info
const redactPaths = [
  'req.headers["x-api-key"]',
  'req.headers["x-admin-key"]',
  'req.headers.authorization',
  'req.headers.cookie',
  '*[*].key',       // Encrypted key material
  '*[*].rawKey',    // Raw key material
  '*[*].secretKey', // Ed25519 secret key
  '*.token',        // Token payloads
  '*.refreshToken'
];

const logger = pino({
  level: config.log.level,
  redact: {
    paths: redactPaths,
    censor: '[REDACTED]',
  },
  ...(config.log.format === 'pretty' && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname',
      },
    },
  }),
});

module.exports = logger;
