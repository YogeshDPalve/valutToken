# ARCHITECTURE.md

## System Overview

VaultToken is a layered Node.js service. Every request passes through:

```
Client
  │
  ▼
[ Rate Limiter ]           — per endpoint, per API key, Redis sliding window
  │
  ▼
[ Request Validator ]      — Zod schema validation on request body
  │
  ▼
[ Auth Middleware ]        — timing-safe API key lookup → resolves tenant
  │
  ▼
[ Controller ]             — orchestrates services, builds response
  │
  ├──▶ KeyService          — fetch active/candidate keys from Redis
  ├──▶ TokenService        — PASETO v4 encrypt / decrypt / sign / verify
  ├──▶ RevocationService   — JTI blocklist, token family tracking
  └──▶ AuditService        — emit structured audit log entry
  │
  ▼
[ Error Handler ]          — map VaultTokenError → HTTP status + JSON
```

---

## Layer Responsibilities

### Config Layer (`src/config/`)
- Parse and validate all environment variables using Zod
- Fail fast on startup if any required variable is missing or invalid
- Export a single typed `config` object used across all layers
- Parse `API_KEYS` string into a `Map<apiKey, tenantId>`
- Convert `KEY_ENCRYPTION_SECRET` hex string into a 32-byte Buffer

### Service Layer (`src/services/`)
Core business logic. No HTTP concerns. Each service takes `(redis, config)`.

**TokenService**
- Implements PASETO v4 local (XChaCha20-Poly1305) and public (Ed25519)
- Builds PAE additional data before every encrypt/sign operation
- Validates standard claims (exp, nbf, iss, aud) after decrypt/verify
- Detects token purpose from prefix — `v4.local.` or `v4.public.`

**KeyService**
- Generates 32-byte random keys for v4.local
- Generates Ed25519 keypairs for v4.public
- Encrypts all key material with AES-256-GCM before writing to Redis
- Decrypts key material on read — never stores plaintext keys
- Implements zero-downtime rotation with configurable grace period
- Returns candidate keys (active + all non-expired retired) for verification

**RevocationService**
- Maintains a Redis sorted set per tenant as the JTI blocklist
- Score = token's original `exp` timestamp — enables TTL-aware range cleanup
- Tracks token families for refresh token reuse detection
- Family state machine: ACTIVE → CONSUMED → REVOKED

**AuditService**
- Writes structured JSON entries to a Redis sorted set (score = ms timestamp)
- Queryable by event type, subject, time range
- Maintains aggregate stat counters in a Redis Hash
- Never logs key material or full token values

### Controller Layer (`src/controllers/`)
- Calls services in the right order
- Builds HTTP response bodies
- Passes errors to Express error handler via `next(err)`
- Records audit log entry on every operation

### Middleware Layer (`src/middleware/`)
- **auth.js** — extracts `X-Api-Key`, compares timing-safely against `config.auth.apiKeys`, sets `req.tenant`
- **rateLimiter.js** — Redis sliding window: ZREMRANGEBYSCORE + ZCARD + ZADD per request
- **errorHandler.js** — maps `VaultTokenError` subclasses to correct HTTP status + JSON body
- **securityHeaders.js** — sets `Cache-Control: no-store`, `X-Content-Type-Options`, etc.

### Route Layer (`src/routes/`)
Thin — just wires middleware + controller method to Express Router. No logic.

---

## PASETO v4 Token Format

```
v4.local.<payload>.<footer>
│  │      │         │
│  │      │         └─ base64url(JSON) — cleartext but PAE-bound
│  │      └─────────── base64url(nonce[24] || ciphertext || tag[16])
│  └────────────────── "local" = encrypted, "public" = signed
└───────────────────── version: v4
```

**v4.public format:**
```
v4.public.<payload>.<footer>
                │
                └─ base64url(message || signature[64])
```

---

## PAE (Pre-Authentication Encoding)

PAE prevents multi-part message attacks by length-prefixing every component before it enters the MAC or signature.

```
PAE(p1, p2, ...) = LE64(n) || LE64(|p1|) || p1 || LE64(|p2|) || p2 || ...
```

- `LE64(n)` = little-endian 64-bit unsigned int
- `n` = number of pieces

**For v4.local encryption:**
```
aad = PAE("v4.local.", nonce, footer, implicitAssertion)
ciphertext = XChaCha20-Poly1305(key, nonce, message, aad)
```

**Why it matters:**
- Changing the header prefix → MAC fails
- Changing the footer → MAC fails (even though footer is cleartext)
- Changing the implicit assertion → MAC fails
- Swapping tokens between different assertion contexts → MAC fails

---

## Data Flows

### Token Issuance

```
POST /tokens/issue
  │
  ├─ Validate body (Zod)
  ├─ Resolve tenant from API key
  ├─ KeyService.getActiveKey(tenant, purpose)
  │     └─ Redis GET → decrypt AES-256-GCM → return raw key buffer
  ├─ TokenService.buildClaims(body)
  │     └─ add iss, iat, nbf, exp, jti (ULID)
  ├─ TokenService.encryptLocal(claims, key, { footer, implicitAssertion })
  │     ├─ random nonce (24 bytes)
  │     ├─ PAE(header, nonce, footer, assertion) → aad
  │     └─ XChaCha20-Poly1305(key, nonce, message, aad) → ciphertext
  ├─ AuditService.log("token.issued", { jti, sub, keyId, ... })
  └─ Response 201 { token, jti, expiresAt, keyId }
```

### Token Verification

```
POST /tokens/verify
  │
  ├─ Detect purpose from token prefix
  ├─ KeyService.getCandidateKeys(tenant, purpose)
  │     └─ active key + all grace-period retired keys
  ├─ TokenService.decryptLocal(token, candidateKeys, { implicitAssertion })
  │     ├─ extract nonce from payload
  │     ├─ PAE(header, nonce, footer, assertion) → aad
  │     ├─ try XChaCha20-Poly1305 decrypt with each candidate key
  │     └─ parse JSON claims from plaintext
  ├─ TokenService.validateClaims(claims)
  │     └─ check exp, nbf, iss, aud
  ├─ RevocationService.isRevoked(jti, tenant)
  │     └─ Redis ZSCORE → null = not revoked
  ├─ AuditService.log("token.verified", ...)
  └─ Response 200 { valid: true, sub, claims, ... }
```

### Key Rotation

```
POST /admin/keys/rotate
  │
  ├─ KeyService.getActiveKey(tenant, purpose) → currentKeyId
  ├─ Move current key to retired:
  │     ├─ Redis SET vaulttoken:keys:{tenant}:{purpose}:retired:{id}
  │     └─ Redis EXPIRE <gracePeriod seconds>
  ├─ KeyService.generateLocalKey / generatePublicKey
  │     ├─ random 32-byte key
  │     ├─ encrypt with AES-256-GCM(KEY_ENCRYPTION_SECRET)
  │     └─ Redis SET vaulttoken:keys:{tenant}:{purpose}:active
  ├─ AuditService.log("key.rotated", { newKeyId, retiredKeyId })
  └─ Response 200 { newKeyId, retiredKeyId, gracePeriodEndsAt }
```

### Refresh Token Reuse Detection

```
Token family state machine:

  createFamily() → familyId
        │
        ▼
  registerRefreshToken(familyId, jti)   ← sets currentRefreshJti = jti
        │
        ▼
  consumeRefreshToken(familyId, jti)
        │
        ├─ family revoked? → reject
        ├─ jti !== currentRefreshJti? → REUSE DETECTED → revoke family → reject
        └─ jti === currentRefreshJti → valid → clear currentRefreshJti → accept
              │
              ▼
        issue new access + refresh token
              │
              ▼
        registerRefreshToken(familyId, newJti)
```

---

## Redis Key Schema

```
# Active key (one per purpose per tenant)
vaulttoken:keys:{tenant}:{purpose}:active
  → JSON { id, version, purpose, key (encrypted), createdAt, tenant }

# Retired keys (auto-expire after grace period)
vaulttoken:keys:{tenant}:{purpose}:retired:{keyId}
  → JSON { id, key (encrypted), retiredAt, expiresAt }
  → TTL = gracePeriod seconds

# Public keys index (safe to expose)
vaulttoken:keys:{tenant}:public:{keyId}
  → JSON { id, publicKey (base64url), createdAt }
vaulttoken:keys:{tenant}:public:index
  → Redis Set of keyIds

# JTI revocation blocklist (sorted set, score = token exp)
vaulttoken:revoked:{tenant}
  → ZADD score=exp member=jti

# Token families
vaulttoken:family:{tenant}:{familyId}
  → JSON { id, currentRefreshJti, memberJtis[], revokedAt }
  → TTL = 30 days

# Audit log (sorted set, score = unix ms)
vaulttoken:audit:{tenant}
  → ZADD score=Date.now() member=JSON(entry)

# Rate limiting (sorted set, score = request timestamp)
vaulttoken:ratelimit:{endpoint}:{clientId}
  → ZADD score=timestamp member=unique

# Blocked keys (emergency revocation)
vaulttoken:keys:blocked
  → Redis Set of keyIds
```

---

## Multi-Tenant Isolation

Every Redis key is namespaced by tenant:

```
vaulttoken:keys:acme-corp:local:active
vaulttoken:revoked:acme-corp
vaulttoken:family:acme-corp:fam_01H...
```

A token issued under `acme-corp` is encrypted with `acme-corp`'s key. Verifying it under `globex`'s key will always fail the MAC check. Cross-tenant acceptance is structurally impossible.

---

## Security Boundaries

```
┌──────────────────────────────────────────────┐
│  TRUST BOUNDARY — VaultToken process         │
│                                              │
│  Private keys NEVER leave this process       │
│  Keys encrypted at rest (AES-256-GCM)        │
│  Keys never appear in logs or HTTP responses │
│  KEY_ENCRYPTION_SECRET loaded from env only  │
│                                              │
│  Public keys: safe to expose at GET /keys    │
└──────────────────────────────────────────────┘
```
