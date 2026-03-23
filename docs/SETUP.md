# SETUP.md

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Node.js | 20.x LTS | Runtime |
| Redis | 7.x | Key store, revocation list, audit log |
| npm | 9.x+ | Package manager |
| Docker (optional) | 24+ | Easiest way to run Redis locally |

---

## 1. Project Initialization

```bash
mkdir vaulttoken && cd vaulttoken
npm init -y
npm install @noble/ciphers @noble/ed25519 @noble/hashes \
  express ioredis zod pino pino-http pino-pretty ulid yargs dotenv
npm install --save-dev jest supertest nodemon eslint prettier
```

---

## 2. Environment Variables

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

### All Variables

```env
# ── Server ──────────────────────────────────────────────
NODE_ENV=development          # development | test | production
PORT=3000
HOST=0.0.0.0

# ── Redis ───────────────────────────────────────────────
REDIS_URL=redis://localhost:6379
REDIS_KEY_PREFIX=vaulttoken:
REDIS_TLS=false               # set true in production

# ── Token Defaults ──────────────────────────────────────
DEFAULT_TOKEN_TTL=3600        # access token lifetime (seconds)
DEFAULT_REFRESH_TTL=604800    # refresh token lifetime (7 days)
DEFAULT_PURPOSE=local         # local | public
DEFAULT_ISSUER=vaulttoken

# ── Key Management ──────────────────────────────────────
KEY_ROTATION_GRACE_PERIOD=86400   # seconds old key stays valid after rotation
KEY_STORAGE=redis                  # redis | file
KEY_FILE_PATH=./keys/keystore.json # used only when KEY_STORAGE=file

# REQUIRED — 32 random bytes encoded as 64 hex characters
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
KEY_ENCRYPTION_SECRET=

# ── API Keys ────────────────────────────────────────────
# Format: apikey:tenantId,apikey2:tenantId2
API_KEYS=your-api-key:default
ADMIN_API_KEY=your-admin-key

# ── Rate Limiting ───────────────────────────────────────
RATE_LIMIT_ISSUE=20           # requests/minute for POST /tokens/issue
RATE_LIMIT_VERIFY=100         # requests/minute for POST /tokens/verify
RATE_LIMIT_REFRESH=10         # requests/minute for POST /tokens/refresh
RATE_LIMIT_REVOKE=20          # requests/minute for POST /tokens/revoke
RATE_LIMIT_WINDOW=60          # window size in seconds

# ── Logging ─────────────────────────────────────────────
LOG_LEVEL=info                # debug | info | warn | error
LOG_FORMAT=pretty             # json | pretty (use json in production)
AUDIT_LOG_FILE=               # optional file path for audit logs

# ── CORS ────────────────────────────────────────────────
CORS_ORIGINS=*                # comma-separated allowed origins

# ── Implicit Assertions ─────────────────────────────────
IMPLICIT_ASSERTION_FIELDS=ip,ua
```

### Generating KEY_ENCRYPTION_SECRET

This is the master key that encrypts all PASETO keys at rest. Generate once:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Never commit this to version control.** Store it in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) in production.

---

## 3. Redis Setup

### Option A — Docker (recommended for development)

```bash
docker-compose up -d redis
# Redis runs on localhost:6379
redis-cli ping  # should return PONG
```

### Option B — Homebrew (macOS)

```bash
brew install redis && brew services start redis
```

### Option C — apt (Ubuntu/Debian)

```bash
sudo apt install redis-server && sudo systemctl start redis
```

### Option D — Redis Cloud / Upstash

Set `REDIS_URL` to your cloud URL and `REDIS_TLS=true`.

---

## 4. Project Scripts (package.json)

```json
{
  "scripts": {
    "start":          "node src/server.js",
    "dev":            "nodemon src/server.js",
    "test":           "jest --runInBand --forceExit",
    "test:unit":      "jest tests/unit --runInBand",
    "test:integration": "jest tests/integration --runInBand",
    "test:e2e":       "jest tests/e2e --runInBand",
    "test:coverage":  "jest --coverage",
    "keygen":         "node scripts/keygen.js",
    "rotate":         "node scripts/rotate.js",
    "revoke":         "node scripts/revoke.js",
    "keys:list":      "node scripts/keys-list.js",
    "audit:tail":     "node scripts/audit-tail.js"
  }
}
```

---

## 5. Key Generation (first run)

Before issuing any tokens you must generate keys:

```bash
npm run keygen
# Generates v4.local + v4.public keys for "default" tenant

npm run keygen -- --type local              # local only
npm run keygen -- --type public             # public only
npm run keygen -- --tenant acme-corp        # for a specific tenant
```

Expected output:
```
✅ Generated v4.local key
   Key ID  : key-v4l-01HXXX...
   Tenant  : default

✅ Generated v4.public key
   Key ID  : key-v4p-01HYYY...
   Public  : (retrieve from GET /keys)
```

---

## 6. Start the Server

```bash
npm run dev         # development with hot reload
npm start           # production
```

Expected output:
```
🔐 VaultToken server started
   port=3000  host=0.0.0.0  env=development
```

---

## 7. Verify Everything Works

```bash
# Health check
curl http://localhost:3000/health

# Issue a token
curl -X POST http://localhost:3000/tokens/issue \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your-api-key" \
  -d '{ "sub": "user_1", "aud": "api.test", "ttl": 300 }'

# Response should start with: { "token": "v4.local...."
```

---

## 8. Docker Compose (full stack)

```yaml
# docker-compose.yml
services:
  vaulttoken:
    build: .
    ports: ["3000:3000"]
    env_file: .env
    depends_on:
      redis:
        condition: service_healthy

  redis:
    image: redis:7-alpine
    volumes: [redis_data:/data]
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s

volumes:
  redis_data:
```

```bash
docker-compose up
```

---

## 9. CLI Reference

```bash
# Key management
npm run keygen                              # generate new keys
npm run keygen -- --tenant acme-corp
npm run rotate                              # rotate active key
npm run rotate -- --type public --grace 172800
npm run keys:list                           # view all key metadata

# Token operations
npm run revoke -- --jti 01HXXX             # revoke by JTI
npm run revoke -- --sub user_42            # revoke all for a user
npm run revoke -- --family fam_01HXXX      # revoke refresh family

# Diagnostics
npm run audit:tail                          # view recent audit entries
npm run audit:tail -- --event token.issued
```

---

## 10. Production Checklist

```
Infrastructure
  [ ] NODE_ENV=production
  [ ] LOG_FORMAT=json
  [ ] LOG_LEVEL=warn

Secrets
  [ ] KEY_ENCRYPTION_SECRET generated (32 random bytes) and stored in secrets manager
  [ ] API_KEYS are long random strings, not guessable
  [ ] ADMIN_API_KEY is separate from API_KEYS and rotated regularly

Redis
  [ ] Redis AUTH password configured
  [ ] REDIS_TLS=true
  [ ] Redis network access restricted to VaultToken process only
  [ ] Redis persistence enabled (AOF or RDB)

Network
  [ ] CORS_ORIGINS set to specific allowed origins (not *)
  [ ] Running behind a reverse proxy (Nginx / Caddy) with TLS termination
  [ ] Rate limits tuned for your expected traffic

Process
  [ ] Running under a process manager (PM2 / systemd)
  [ ] Health check endpoint monitored
  [ ] Alerts on key rotation, emergency revocation events

Keys
  [ ] Key rotation schedule set (recommended: every 30-90 days)
  [ ] Backup strategy for Redis data
```
