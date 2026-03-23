# API.md

## Base URL
```
http://localhost:3000
```

## Authentication

All endpoints except `GET /health` and `GET /keys` require:
```
X-Api-Key: your-api-key
```

Admin endpoints additionally require:
```
X-Admin-Key: your-admin-key
```

---

## Endpoints

---

### GET /health

No authentication required.

**Response 200**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "redis": "connected",
  "uptime": 3600,
  "keys": {
    "local": 1,
    "public": 1
  }
}
```

---

### POST /tokens/issue

Issue a new PASETO v4 token.

**Rate limit:** `RATE_LIMIT_ISSUE` req/min per API key

**Request body**

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `sub` | string | ✅ | — | Subject — user ID, service ID |
| `aud` | string | ✅ | — | Audience — intended recipient |
| `purpose` | string | ❌ | `"local"` | `"local"` or `"public"` |
| `ttl` | integer | ❌ | `3600` | Token lifetime in seconds (max 2592000) |
| `claims` | object | ❌ | `{}` | Custom payload claims |
| `footer` | object/string | ❌ | `{ kid }` | Cleartext footer metadata |
| `implicitAssertion` | string | ❌ | `""` | Context bound to token, verified at validation |
| `refreshable` | boolean | ❌ | `false` | Also issue a refresh token |
| `familyId` | string | ❌ | auto | Token family ID for refresh tracking |

**Example request**
```json
{
  "sub": "user_42",
  "aud": "api.myapp.com",
  "purpose": "local",
  "ttl": 3600,
  "claims": {
    "role": "admin",
    "plan": "pro"
  },
  "refreshable": true,
  "implicitAssertion": "ip:1.2.3.4|ua:MyApp/1.0"
}
```

**Response 201**
```json
{
  "token": "v4.local.QAxIpVe-ECVNI1z...",
  "jti": "01HXXX123ABC",
  "purpose": "local",
  "keyId": "key-v4l-01HXXX",
  "issuedAt": "2025-01-15T10:00:00.000Z",
  "expiresAt": "2025-01-15T11:00:00.000Z",
  "refreshToken": "v4.local.refreshtokenhere...",
  "refreshExpiresAt": "2025-01-22T10:00:00.000Z",
  "familyId": "fam_01HXXX"
}
```

> `refreshToken` and `familyId` are only present when `refreshable: true`

---

### POST /tokens/verify

Decrypt and validate a token. Returns claims if valid.

**Rate limit:** `RATE_LIMIT_VERIFY` req/min

**Request body**

| Field | Type | Required | Notes |
|---|---|---|---|
| `token` | string | ✅ | The PASETO token to verify |
| `aud` | string | ❌ | Expected audience — validated against `aud` claim |
| `implicitAssertion` | string | ❌ | Must match assertion used at issuance |

**Example request**
```json
{
  "token": "v4.local.QAxIpVe-ECVNI1z...",
  "aud": "api.myapp.com",
  "implicitAssertion": "ip:1.2.3.4|ua:MyApp/1.0"
}
```

**Response 200**
```json
{
  "valid": true,
  "jti": "01HXXX123ABC",
  "sub": "user_42",
  "iss": "vaulttoken",
  "aud": "api.myapp.com",
  "iat": "2025-01-15T10:00:00.000Z",
  "exp": "2025-01-15T11:00:00.000Z",
  "nbf": "2025-01-15T10:00:00.000Z",
  "claims": {
    "role": "admin",
    "plan": "pro"
  },
  "purpose": "local",
  "keyId": "key-v4l-01HXXX"
}
```

---

### POST /tokens/refresh

Exchange a refresh token for a new access + refresh token pair. The old refresh token is immediately invalidated (rotation-on-use). If the same refresh token is presented twice, the entire family is revoked.

**Rate limit:** `RATE_LIMIT_REFRESH` req/min

**Request body**

| Field | Type | Required | Notes |
|---|---|---|---|
| `refreshToken` | string | ✅ | The refresh token to exchange |
| `implicitAssertion` | string | ❌ | Must match assertion from issuance |

**Response 200**
```json
{
  "token": "v4.local.newaccesstoken...",
  "jti": "01HYYY456DEF",
  "expiresAt": "2025-01-15T12:00:00.000Z",
  "refreshToken": "v4.local.newrefreshtoken...",
  "refreshJti": "01HYYY789GHI",
  "refreshExpiresAt": "2025-01-22T11:00:00.000Z",
  "familyId": "fam_01HXXX"
}
```

**Response 401 — reuse detected**
```json
{
  "error": "REFRESH_REUSE_DETECTED",
  "message": "Refresh token already used — possible token theft. Family revoked.",
  "familyId": "fam_01HXXX"
}
```

> When reuse is detected, the user must log in again.

---

### POST /tokens/revoke

Add a token's JTI to the revocation blocklist.

**Rate limit:** `RATE_LIMIT_REVOKE` req/min

**Request body** — provide `jti` OR `token`, not both required

| Field | Type | Notes |
|---|---|---|
| `jti` | string | Revoke by JTI directly |
| `token` | string | Server will decrypt to extract JTI |
| `reason` | string | Optional — logged in audit trail |

**Example — by JTI**
```json
{ "jti": "01HXXX123ABC", "reason": "user_logout" }
```

**Example — by token**
```json
{ "token": "v4.local.QAxIpVe...", "reason": "compromised" }
```

**Response 200**
```json
{
  "revoked": true,
  "jti": "01HXXX123ABC",
  "revokedAt": "2025-01-15T10:30:00.000Z"
}
```

---

### POST /tokens/introspect

RFC 7662-style introspection. Returns `{ active: false }` for any invalid, expired, or revoked token — never an error response.

**Request body**

| Field | Type | Notes |
|---|---|---|
| `token` | string | Token to introspect |
| `token_type_hint` | string | `"access_token"` or `"refresh_token"` |

**Response 200 — active**
```json
{
  "active": true,
  "sub": "user_42",
  "aud": "api.myapp.com",
  "iss": "vaulttoken",
  "exp": 1705313400,
  "iat": 1705309800,
  "jti": "01HXXX123ABC",
  "token_type": "access_token"
}
```

**Response 200 — inactive**
```json
{ "active": false }
```

---

### GET /keys

Retrieve active public Ed25519 keys for v4.public token verification.

**No authentication required.** Safe to expose publicly.

**Response 200**
```json
{
  "keys": [
    {
      "kid": "key-v4p-01HXXX",
      "kty": "OKP",
      "crv": "Ed25519",
      "use": "sig",
      "alg": "EdDSA",
      "x": "base64url-encoded-32-byte-public-key",
      "createdAt": "2025-01-15T00:00:00.000Z"
    }
  ]
}
```

---

### POST /keys/rotate *(Admin)*

Zero-downtime key rotation. Requires `X-Admin-Key`.

**Request body**

| Field | Type | Default | Notes |
|---|---|---|---|
| `purpose` | string | `"local"` | `"local"` or `"public"` |
| `gracePeriod` | integer | env value | Seconds old key stays valid |
| `tenant` | string | `"default"` | Target tenant |

**Response 200**
```json
{
  "newKeyId": "key-v4l-01HYYY",
  "retiredKeyId": "key-v4l-01HXXX",
  "gracePeriodEndsAt": "2025-01-16T10:00:00.000Z",
  "rotatedAt": "2025-01-15T10:00:00.000Z"
}
```

---

### GET /admin/keys *(Admin)*

List all key metadata. No key material returned.

**Query params:** `?tenant=default`

**Response 200**
```json
{
  "active": [
    { "id": "key-v4l-01HYYY", "purpose": "local", "version": "v4", "createdAt": "..." }
  ],
  "retired": [
    { "id": "key-v4l-01HXXX", "purpose": "local", "retiredAt": "...", "expiresAt": "..." }
  ]
}
```

---

### POST /admin/keys/emergency-revoke *(Admin)*

Immediately invalidate a key with no grace period. All tokens issued with this key are rejected instantly.

**Request body**
```json
{ "keyId": "key-v4l-01HXXX", "purpose": "local", "tenant": "default" }
```

**Response 200**
```json
{
  "revoked": true,
  "keyId": "key-v4l-01HXXX",
  "revokedAt": "2025-01-15T10:00:00.000Z",
  "message": "All tokens issued with this key will now be rejected."
}
```

---

### GET /admin/audit *(Admin)*

Query the audit log.

**Query params**

| Param | Default | Notes |
|---|---|---|
| `tenant` | `"default"` | |
| `event` | all | e.g. `token.issued`, `token.verify_failed` |
| `sub` | all | Filter by subject |
| `since` | 24h ago | ISO timestamp |
| `limit` | 50 | Max results |

**Response 200**
```json
{
  "entries": [
    {
      "ts": "2025-01-15T10:23:45.123Z",
      "event": "token.issued",
      "jti": "01HXXX",
      "sub": "user_42",
      "purpose": "local",
      "keyId": "key-v4l-01HXXX",
      "latencyMs": 2.4
    }
  ],
  "total": 1
}
```

---

### GET /admin/stats *(Admin)*

Aggregate token operation statistics.

**Response 200**
```json
{
  "issued":   { "total": 10423 },
  "verified": { "total": 89234 },
  "revoked":  { "total": 12 },
  "failed":   { "total": 45 },
  "refreshed":{ "total": 3210 },
  "activeRevocations": 5,
  "activeKeys": { "local": 1, "public": 1 }
}
```

---

## Error Reference

| Code | HTTP | When |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Request body fails schema validation |
| `UNAUTHORIZED` | 401 | Missing or invalid API key |
| `TOKEN_INVALID` | 401 | MAC/signature check failed |
| `TOKEN_EXPIRED` | 401 | Token past its `exp` |
| `TOKEN_NOT_YET_VALID` | 401 | Token before its `nbf` |
| `TOKEN_REVOKED` | 401 | JTI found in revocation set |
| `AUDIENCE_MISMATCH` | 401 | `aud` claim does not match expected |
| `ISSUER_MISMATCH` | 401 | `iss` claim does not match expected |
| `ASSERTION_MISMATCH` | 401 | Implicit assertion did not match |
| `REFRESH_REUSE_DETECTED` | 401 | Refresh token presented twice |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `NO_ACTIVE_KEY` | 500 | No active key for the requested purpose |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

**Error response shape**
```json
{
  "error": "TOKEN_EXPIRED",
  "message": "Token has expired",
  "expiredAt": "2025-01-15T09:00:00.000Z"
}
```

---

## Standard Claims

PASETO uses the same registered claims as JWT:

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Issuer — who created the token |
| `sub` | string | Subject — who the token represents |
| `aud` | string | Audience — intended recipient |
| `exp` | integer | Expiration — Unix timestamp |
| `nbf` | integer | Not Before — Unix timestamp |
| `iat` | integer | Issued At — Unix timestamp |
| `jti` | string | JWT ID — unique token identifier (ULID) |
