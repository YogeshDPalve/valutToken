require('dotenv').config();
const { z } = require('zod');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default('0.0.0.0'),

  REDIS_URL: z.string().url(),
  REDIS_KEY_PREFIX: z.string().default('vaulttoken:'),
  REDIS_TLS: z.coerce.boolean().default(false),

  DEFAULT_TOKEN_TTL: z.coerce.number().int().positive().default(3600),
  DEFAULT_REFRESH_TTL: z.coerce.number().int().positive().default(604800),
  DEFAULT_PURPOSE: z.enum(['local', 'public']).default('local'),
  DEFAULT_ISSUER: z.string().default('vaulttoken'),

  KEY_ROTATION_GRACE_PERIOD: z.coerce.number().int().nonnegative().default(86400),
  KEY_STORAGE: z.enum(['redis', 'file']).default('redis'),
  KEY_FILE_PATH: z.string().default('./keys/keystore.json'),

  KEY_ENCRYPTION_SECRET: z.string().length(64).regex(/^[0-9a-fA-F]{64}$/, 'Must be a 64-character hex string'),

  API_KEYS: z.string().min(1),
  ADMIN_API_KEY: z.string().min(1),

  RATE_LIMIT_ISSUE: z.coerce.number().int().positive().default(20),
  RATE_LIMIT_VERIFY: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_REFRESH: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_REVOKE: z.coerce.number().int().positive().default(20),
  RATE_LIMIT_WINDOW: z.coerce.number().int().positive().default(60),

  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  LOG_FORMAT: z.enum(['json', 'pretty']).default('pretty'),
  AUDIT_LOG_FILE: z.string().optional(),

  CORS_ORIGINS: z.string().default('*'),

  IMPLICIT_ASSERTION_FIELDS: z.string().default('ip,ua'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment variables:', JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1);
}

const env = parsed.data;

// Parse API_KEYS into a map of apiKey -> tenantId
const apiKeysMap = new Map();
const keysList = env.API_KEYS.split(',');
for (const entry of keysList) {
  const [apiKey, tenantId] = entry.split(':');
  if (!apiKey || !tenantId) {
    console.error('❌ Invalid API_KEYS format. Expected apiKey:tenantId,apiKey2:tenantId2');
    process.exit(1);
  }
  apiKeysMap.set(apiKey.trim(), tenantId.trim());
}

// Parse implicit assertions
const implicitAssertionFields = env.IMPLICIT_ASSERTION_FIELDS.split(',').map(f => f.trim()).filter(Boolean);

const config = {
  env: env.NODE_ENV,
  server: {
    port: env.PORT,
    host: env.HOST,
  },
  redis: {
    url: env.REDIS_URL,
    prefix: env.REDIS_KEY_PREFIX,
    tls: env.REDIS_TLS,
  },
  token: {
    defaultTtl: env.DEFAULT_TOKEN_TTL,
    defaultRefreshTtl: env.DEFAULT_REFRESH_TTL,
    defaultPurpose: env.DEFAULT_PURPOSE,
    defaultIssuer: env.DEFAULT_ISSUER,
  },
  keys: {
    rotationGracePeriod: env.KEY_ROTATION_GRACE_PERIOD,
    storage: env.KEY_STORAGE,
    filePath: env.KEY_FILE_PATH,
    encryptionSecret: Buffer.from(env.KEY_ENCRYPTION_SECRET, 'hex'), // 32-byte buffer
  },
  auth: {
    apiKeys: apiKeysMap,
    adminApiKey: env.ADMIN_API_KEY,
  },
  rateLimit: {
    issue: env.RATE_LIMIT_ISSUE,
    verify: env.RATE_LIMIT_VERIFY,
    refresh: env.RATE_LIMIT_REFRESH,
    revoke: env.RATE_LIMIT_REVOKE,
    window: env.RATE_LIMIT_WINDOW,
  },
  log: {
    level: env.LOG_LEVEL,
    format: env.LOG_FORMAT,
    auditFile: env.AUDIT_LOG_FILE,
  },
  cors: {
    origins: env.CORS_ORIGINS === '*' ? '*' : env.CORS_ORIGINS.split(',').map(o => o.trim()),
  },
  security: {
    implicitAssertionFields,
  }
};

module.exports = config;
