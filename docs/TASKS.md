# TASKS.md — Implementation Checklist

Work through these tasks in order. Each phase builds on the previous.

---

## Phase 1 — Project Setup

- [x] `npm init -y`
- [x] Install all dependencies (see README.md → Core Dependencies)
- [x] Create folder structure: `src/config`, `src/services`, `src/controllers`, `src/middleware`, `src/routes`, `src/utils`, `src/validators`, `tests/unit`, `tests/integration`, `tests/e2e`, `scripts`
- [x] Create `.env` from `.env.example` — fill in `KEY_ENCRYPTION_SECRET` and `API_KEYS`
- [x] Add `jest`, `eslint`, `prettier` config to `package.json`
- [x] Add all npm scripts to `package.json` (see SETUP.md → Project Scripts)
- [x] Set up `nodemon` for development

---

## Phase 2 — Config & Utilities

### `src/config/index.js`
- [x] Define Zod schema for all env variables
- [x] Call `safeParse(process.env)` — exit process on failure with clear error messages
- [x] Parse `API_KEYS` string into `Map<apiKey, tenantId>`
- [x] Convert `KEY_ENCRYPTION_SECRET` hex string to 32-byte Buffer
- [x] Export a single typed `config` object

### `src/utils/errors.js`
- [x] Create base `VaultTokenError` class extending `Error` with `code`, `statusCode`, `details`
- [x] Create subclasses for each error type listed in API.md → Error Reference
- [x] All subclasses must call `Error.captureStackTrace`

### `src/utils/pae.js`
- [x] Implement `le64(n)` — encode number as 8-byte little-endian Buffer
- [x] Implement `pae(...pieces)` — length-prefix encode each piece, concat with count prefix
- [x] Accept Buffer, Uint8Array, or string inputs — throw TypeError for anything else
- [x] Write unit tests first (see tests/unit/pae.test.js) — use spec test vectors

### `src/utils/logger.js`
- [x] Create Pino logger with `LOG_LEVEL` and `LOG_FORMAT` from config
- [x] Add redact paths for API keys, secrets, key material
- [x] Export singleton logger

---

## Phase 3 — Core Services

### `src/services/KeyService.js`

**Constructor:** takes `(redis, config)`

**Key ID generation:**
- [x] `_makeKeyId(purpose)` — format: `key-v4{l|p}-{ULID}`

**Encryption at rest:**
- [x] `_encryptMaterial(rawBytes)` — AES-256-GCM with random 12-byte IV, return `base64(iv || tag || ciphertext)`
- [x] `_decryptMaterial(stored)` — reverse the above, throw `KeyDecryptionError` on auth tag failure

**Generation:**
- [x] `generateLocalKey({ tenant })` — `crypto.randomBytes(32)`, encrypt, write to Redis active slot, return `{ id, tenant, createdAt }`
- [x] `generatePublicKey({ tenant })` — Ed25519 keypair via `@noble/ed25519`, encrypt secret key, write secret + public records, return `{ id, publicKey, tenant, createdAt }`

**Retrieval:**
- [x] `getActiveKey(tenant, purpose)` — GET from Redis, decrypt, return `{ id, purpose, rawKey, publicKey? }`
- [x] `getCandidateKeys(tenant, purpose)` — active key + all non-expired retired keys (scan by pattern)
- [x] `getKeyById(tenant, purpose, keyId)` — check active first, then retired

**Rotation:**
- [x] `rotateKey(tenant, purpose, gracePeriod)` — retire current active (with TTL), generate new active, return `{ newKeyId, retiredKeyId, gracePeriodEndsAt }`
- [x] `_retireExistingActive(tenant, purpose)` — internal: move active → retired with Redis EXPIRE
- [x] `_storeRetiredKey(tenant, purpose, record, gracePeriod)` — internal: SET + EXPIRE

**Public keys:**
- [x] `getPublicKeys(tenant)` — return JWKS-style array (kty, crv, use, alg, x, kid)
- [x] `listKeys(tenant)` — return `{ active: [...], retired: [...] }` with no key material

**Emergency:**
- [x] `emergencyRevokeKey(tenant, purpose, keyId)` — delete from active + retired, SADD to blocked set
- [x] `isKeyBlocked(keyId)` — SISMEMBER on blocked set

---

### `src/services/TokenService.js`

**Constructor:** takes `(config)`

**Claims:**
- [x] `buildClaims(body, options)` — assemble `{ iss, sub, aud, iat, nbf, exp, jti, typ, fid?, ...customClaims }`
  - `jti` = ULID
  - `exp` = `now + ttl`
  - `typ` = `"access"` or `"refresh"` based on `options.isRefresh`
  - `fid` = `options.familyId` if provided

- [x] `validateClaims(claims, options)` — check `exp` (throw `TokenExpiredError`), `nbf` (throw `TokenNotYetValidError`), `iss` (throw `IssuerMismatchError`), `aud` (throw `AudienceMismatchError`)

**v4.local:**
- [x] `encryptLocal(claims, key, options)`:
  1. Serialize claims to JSON Buffer
  2. Generate 24-byte random nonce
  3. Serialize footer to Buffer
  4. Serialize implicitAssertion to Buffer (empty string if absent)
  5. `aad = PAE("v4.local.", nonce, footerBuf, assertionBuf)`
  6. `ciphertext = XChaCha20Poly1305(key, nonce, aad).encrypt(message)`
  7. Return `"v4.local." + base64url(nonce || ciphertext) + "." + base64url(footer)`

- [x] `decryptLocal(token, key|keys, options)`:
  1. Check token starts with `"v4.local."` — else throw `TokenInvalidError`
  2. Split on `.` — extract payload (index 2) and footer (index 3)
  3. Decode payload → split nonce (first 24 bytes) and ciphertext (rest)
  4. Build same PAE aad
  5. Try decrypt with each candidate key — MAC failure → try next
  6. If all fail → throw `TokenInvalidError` or `AssertionMismatchError`
  7. Parse JSON from plaintext
  8. Call `validateClaims`

**v4.public:**
- [x] `signPublic(claims, secretKey, options)`:
  1. Serialize claims to JSON Buffer (= `m`)
  2. `m2 = PAE("v4.public.", m, footerBuf, assertionBuf)`
  3. `sig = Ed25519.sign(m2, secretKey)` — 64 bytes
  4. Return `"v4.public." + base64url(m || sig) + "." + base64url(footer)`

- [x] `verifyPublic(token, publicKey|keys, options)`:
  1. Check prefix `"v4.public."`
  2. Decode payload → split message (all bytes except last 64) and signature (last 64)
  3. Build same PAE `m2`
  4. `Ed25519.verify(sig, m2, publicKey)` — try each candidate key
  5. If none verify → throw `TokenInvalidError`
  6. Parse JSON from message
  7. Call `validateClaims`

**Helpers:**
- [x] `issue(claims, keyRecord, options)` — dispatch to local or public based on `keyRecord.purpose`
- [x] `verify(token, candidateKeys, options)` — dispatch based on token prefix
- [x] `detectPurpose(token)` — return `"local"`, `"public"`, or `null`
- [x] `parseFooter(token)` — base64url decode part[3], try JSON parse

---

### `src/services/RevocationService.js`

**Constructor:** takes `(redis, config)`

**JTI blocklist:**
- [x] `revoke(jti, tenant, expiresAt, meta)` — `ZADD revoked:{tenant} {exp} {jti}`, optionally track by subject, call `_cleanupExpired`
- [x] `isRevoked(jti, tenant)` — `ZSCORE revoked:{tenant} {jti}` — non-null = revoked
- [x] `revokeBySubject(sub, tenant)` — add sentinel entry to revoked set and subject index
- [x] `revokeByKey(keyId, tenant)` — `SADD revoked:key:{tenant} {keyId}`
- [x] `isKeyRevoked(keyId, tenant)` — `SISMEMBER revoked:key:{tenant} {keyId}`
- [x] `_cleanupExpired(tenant)` — `ZREMRANGEBYSCORE revoked:{tenant} -inf {now-1}`

**Token families:**
- [x] `createFamily(tenant)` — generate `fam_{ULID}`, write JSON record with TTL 30 days
- [x] `registerRefreshToken(familyId, jti, tenant)` — set `currentRefreshJti = jti` in family record
- [x] `consumeRefreshToken(familyId, jti, tenant)`:
  - Family missing → `{ valid: false, reuseDetected: false }`
  - `record.revokedAt` set → `{ valid: false, reuseDetected: true }`
  - `jti !== currentRefreshJti` → set `revokedAt`, return `{ valid: false, reuseDetected: true }`
  - `jti === currentRefreshJti` → clear `currentRefreshJti`, return `{ valid: true, reuseDetected: false }`
- [x] `isFamilyRevoked(familyId, tenant)` — check `record.revokedAt`
- [x] `revokeFamily(familyId, tenant)` — set `revokedAt` on family record

---

### `src/services/AuditService.js`

**Constructor:** takes `(redis, config)`

- [x] Define event constants: `token.issued`, `token.verified`, `token.verify_failed`, `token.revoked`, `token.refreshed`, `refresh.reuse_detected`, `key.generated`, `key.rotated`, `key.retired`, `key.emergency_revoked`
- [x] `log(event, data)` — remove sensitive fields, emit to Pino logger, `ZADD audit:{tenant} {Date.now()} {JSON}`, `HINCRBY stats:{tenant} {event} 1`, trim to max entries
- [x] `query(filters)` — `ZRANGEBYSCORE` with time range, filter by event/sub in memory, reverse sort, limit
- [x] `getStats(tenant)` — `HGETALL stats:{tenant}`, parse to numbers, include `ZCARD revoked:{tenant}`

---

## Phase 4 — Middleware

### `src/middleware/auth.js`
- [x] `auth(config)` — extract `X-Api-Key`, iterate `config.auth.apiKeys` with `crypto.timingSafeEqual`, set `req.tenant`, call `next(new UnauthorizedError)` on failure
- [x] `adminAuth(config)` — extract `X-Admin-Key`, timing-safe compare against `config.auth.adminApiKey`

### `src/middleware/rateLimiter.js`
- [x] `rateLimiter(redis, { limit, windowSeconds, prefix, endpoint })`:
  1. Key = `{prefix}ratelimit:{endpoint}:{req.tenant ?? req.ip}`
  2. Pipeline: ZREMRANGEBYSCORE (remove old), ZCARD (count), ZADD (add current), EXPIRE
  3. Set `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers
  4. If count >= limit → `next(new RateLimitError(retryAfter))`
  5. On Redis failure → fail open (call `next()`)

### `src/middleware/errorHandler.js`
- [x] Map `VaultTokenError` → `res.status(err.statusCode).json({ error: err.code, message: err.message, ...err.details })`
- [x] Map `ZodError` → `400 VALIDATION_ERROR` with field-level details
- [x] Unknown errors → `500 INTERNAL_ERROR` (never leak stack trace)

### `src/middleware/securityHeaders.js`
- [x] Set all headers listed in SECURITY.md → Security Headers on every response

---

## Phase 5 — Controllers

### `src/controllers/TokenController.js`

Each method takes `(req, res, next)`:

- [x] `issue` — validate body → getActiveKey → buildClaims → issue token → (optionally issue refresh + create family) → log audit → 201
- [x] `verify` — detectPurpose → getCandidateKeys → verify token → validateClaims → isRevoked → isKeyRevoked → log audit → 200
- [x] `refresh` — verify refresh token → check `typ === "refresh"` → consumeRefreshToken → detect reuse → revoke old JTI → issue new pair → registerRefreshToken → log audit → 200
- [x] `revoke` — extract JTI (from body or by decrypting token) → revoke → log audit → 200
- [x] `introspect` — try verify → isRevoked → return `{ active }` (never throw — always 200)

### `src/controllers/KeyController.js`

- [x] `getPublicKeys` — getPublicKeys(tenant) → 200
- [x] `rotate` — rotateKey → log audit → 200
- [x] `list` — listKeys(tenant) → 200
- [x] `emergencyRevoke` — emergencyRevokeKey → log audit → 200

### `src/controllers/AdminController.js`

- [x] `getAuditLog` — query(filters from req.query) → 200
- [x] `getStats` — getStats(tenant) + listKeys → 200
- [x] `revokeBySubject` — revokeBySubject → 200
- [x] `revokeFamily` — revokeFamily → 200

---

## Phase 6 — Routes & App

### `src/validators/schemas.js`
- [x] Define Zod schemas for each endpoint body: `issueSchema`, `verifySchema`, `refreshSchema`, `revokeSchema`, `introspectSchema`, `rotateSchema`
- [x] Create `validate(schema)` middleware factory that calls `schema.safeParse(req.body)` and calls `next(err)` on failure

### `src/routes/`
- [x] `tokens.js` — POST /issue, /verify, /refresh, /revoke, /introspect — each with rate limiter + validate middleware
- [x] `keys.js` — GET / (no auth), POST /rotate + GET /all + POST /emergency-revoke (adminAuth)
- [x] `admin.js` — GET /audit, GET /stats, POST /revoke/subject, POST /revoke/family

### `src/app.js`
- [x] Instantiate all services and controllers
- [x] Mount middleware in order: security headers → JSON body parser → correlation ID → request logger → CORS → routes → 404 → error handler
- [x] Export `createApp(redis)` factory

### `src/server.js`
- [x] Create Redis client (with retry strategy)
- [x] Call `createApp(redis)`
- [x] `server.listen(port, host)`
- [x] Handle `SIGTERM` and `SIGINT` — close HTTP server, quit Redis, exit 0
- [x] Handle `uncaughtException` and `unhandledRejection` — log fatal, exit 1

---

## Phase 7 — CLI Scripts

### `scripts/keygen.js`
- [ ] Parse `--type`, `--tenant`, `--show-public` flags with yargs
- [ ] Connect to Redis, call `KeyService.generateLocalKey` and/or `generatePublicKey`
- [ ] Print key IDs and metadata, disconnect

### `scripts/rotate.js`
- [ ] Parse `--type`, `--tenant`, `--grace`, `--yes` flags
- [ ] If production and not `--yes`, prompt for confirmation
- [ ] Call `KeyService.rotateKey`, print before/after

### `scripts/revoke.js`
- [ ] Parse `--jti`, `--sub`, `--family`, `--key`, `--tenant`, `--reason` flags
- [ ] Call the appropriate `RevocationService` method

### `scripts/keys-list.js`
- [ ] Parse `--tenant` flag
- [ ] Call `KeyService.listKeys` and `getPublicKeys`
- [ ] Print colored table of active, retired, and public keys

### `scripts/audit-tail.js`
- [ ] Parse `--tenant`, `--event`, `--limit` flags
- [ ] Call `AuditService.query` with filters
- [ ] Print colored log lines

---

## Phase 8 — Tests

### Unit tests (`tests/unit/`)

- [ ] `pae.test.js` — test against official PASETO spec test vectors:
  - `PAE()` → `0x0000000000000000`
  - `PAE("")` → `0x0100000000000000 0x0000000000000000`
  - Multi-piece ambiguity prevention (splitting same bytes differently → different output)

- [ ] `TokenService.test.js`:
  - Encrypt/decrypt round trip (local)
  - Sign/verify round trip (public)
  - Payload is not readable as plaintext after encryption
  - Wrong key → `TokenInvalidError`
  - Tampered ciphertext → `TokenInvalidError`
  - Footer tampering → `TokenInvalidError`
  - Expired token → `TokenExpiredError`
  - Wrong implicit assertion → error
  - Correct implicit assertion → success
  - Audience mismatch → `AudienceMismatchError`
  - Candidate key fallback (verify with retired key)
  - Different tokens produced for same claims (random nonce)

- [ ] `RevocationService.test.js`:
  - Revoke + isRevoked round trip
  - Non-revoked JTI returns false
  - Family: create → register → consume (valid)
  - Family: reuse detection (same JTI twice)
  - Family: replay after rotation revokes family
  - Explicit family revocation

- [ ] `KeyService.test.js`:
  - generateLocalKey returns correct ID format
  - getActiveKey returns 32-byte rawKey Buffer
  - Key material is AES-encrypted at rest (raw Redis value is not a plaintext key)
  - rotateKey: new key becomes active, old key goes to retired
  - getCandidateKeys returns active + retired
  - getPublicKeys returns JWKS-style keys

### Integration tests (`tests/integration/`)

- [ ] POST /tokens/issue — success, missing sub, missing aud, bad API key, TTL respected
- [ ] POST /tokens/verify — valid, tampered, wrong aud, revoked, wrong assertion, correct assertion
- [ ] POST /tokens/refresh — success, reuse detection, non-refresh token rejected
- [ ] POST /tokens/revoke — by JTI, by token, missing both → 400
- [ ] POST /tokens/introspect — active, invalid, revoked → always 200
- [ ] GET /keys — no auth required, returns OKP keys
- [ ] POST /keys/rotate — success, wrong admin key → 401
- [ ] GET /admin/stats — requires admin key
- [ ] GET /admin/audit — returns entries

### E2E tests (`tests/e2e/`)

- [ ] Full login → verify → refresh → logout cycle
- [ ] Key rotation: issue before rotation → rotate → verify during grace → new tokens use new key
- [ ] Refresh token reuse attack: issue → use → replay old → family revoked → new token also fails
- [ ] Implicit assertion: issue with assertion → verify with correct → verify with wrong → fail
- [ ] Multi-tenant: tenant-A token fails under tenant-B key

---

## Phase 9 — Docker & Deployment

- [ ] `Dockerfile` — multi-stage (install deps → copy src), non-root user, `HEALTHCHECK`
- [ ] `docker-compose.yml` — vaulttoken service + Redis 7 with health check + named volume
- [ ] `.gitignore` — exclude `node_modules/`, `.env`, `keys/`, `coverage/`

---

## Suggested Implementation Order

```
Phase 2 utils (errors, pae, logger)  ← foundation
    ↓
Phase 3 KeyService                   ← needed by everything
    ↓
Phase 3 TokenService                 ← core PASETO logic
    ↓
Phase 3 RevocationService            ← needed by verify flow
    ↓
Phase 3 AuditService                 ← needed by controllers
    ↓
Phase 4 Middleware                   ← needed by routes
    ↓
Phase 5 Controllers                  ← business logic
    ↓
Phase 6 Routes + App + Server        ← HTTP layer
    ↓
Phase 7 CLI scripts                  ← operational tooling
    ↓
Phase 8 Tests                        ← verify everything
    ↓
Phase 9 Docker                       ← deployment
```

Start writing tests for each service **before** implementing it — the test forces you to understand the exact inputs and outputs required.
