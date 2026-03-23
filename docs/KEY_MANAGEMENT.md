# KEY_MANAGEMENT.md

## Key Types

| Type | Algorithm | Key Material | Use |
|---|---|---|---|
| `v4.local` | XChaCha20-Poly1305 | 32-byte random | Encrypt token payload |
| `v4.public` | Ed25519 | 64-byte secret, 32-byte public | Sign token payload |

---

## Key ID Format

```
key-v4l-01HXXX...    ← local key
key-v4p-01HYYY...    ← public key
     │    └─────── ULID (26 chars, monotonically sortable)
     └──────────── v4 version + l/p purpose indicator
```

ULIDs are used because they are:
- Lexicographically sortable — newest key sorts last
- URL-safe — no special characters
- Monotonically increasing — no collision risk
- Human readable — includes timestamp component

---

## Key Lifecycle

```
GENERATED
    │
    ▼
  ACTIVE ──── rotation triggered ────▶ RETIRED (with grace TTL)
    │                                      │
    │                                      ▼
    │                              TTL expires → auto-purged from Redis
    │
    └──── emergency revoke ────▶ BLOCKED (permanent blocklist)
```

### State Descriptions

| State | Description | Stored at |
|---|---|---|
| ACTIVE | Used for all new token issuance | `keys:{tenant}:{purpose}:active` |
| RETIRED | Old tokens still verifiable; new tokens use new key | `keys:{tenant}:{purpose}:retired:{keyId}` |
| BLOCKED | Emergency revocation — all tokens immediately rejected | `keys:blocked` (Redis Set) |

---

## Generating Keys

```bash
npm run keygen                          # both local + public, default tenant
npm run keygen -- --type local          # local only
npm run keygen -- --type public         # public only
npm run keygen -- --tenant acme-corp    # for specific tenant
npm run keygen -- --show-public         # print public key bytes
```

### What keygen does internally

1. Generate 32 random bytes (local) or Ed25519 keypair (public)
2. Encrypt key material with `AES-256-GCM(KEY_ENCRYPTION_SECRET)`
3. Wrap in a key record JSON: `{ id, version, purpose, key (encrypted), createdAt, tenant }`
4. Move any existing active key to retired state (with grace period TTL)
5. Write new record to `vaulttoken:keys:{tenant}:{purpose}:active`
6. For public keys: also write public key to `vaulttoken:keys:{tenant}:public:{keyId}` and add to index set

---

## Key Rotation

### When to rotate

- **Scheduled** — every 30–90 days as standard hygiene
- **Employee offboarding** — when someone with key access leaves
- **Suspected compromise** — if you believe key material may have been exposed
- **Infrastructure migration** — moving to new hardware or secrets manager

### Rotation command

```bash
npm run rotate                              # rotate local key, default tenant
npm run rotate -- --type public            # rotate public key
npm run rotate -- --grace 172800           # 48-hour grace period
npm run rotate -- --tenant acme-corp       # specific tenant
npm run rotate -- --yes                    # skip confirmation in production
```

### What happens during rotation

```
Before:
  ACTIVE: key-v4l-01HAAA

Step 1: Move current active key to RETIRED
  vaulttoken:keys:default:local:retired:key-v4l-01HAAA
  Redis EXPIRE set to gracePeriod (default 86400s)

Step 2: Generate new key
  vaulttoken:keys:default:local:active  ← key-v4l-01HBBB

After:
  ACTIVE:  key-v4l-01HBBB  ← all new tokens use this
  RETIRED: key-v4l-01HAAA  ← old tokens still verifiable for 24h
  (24h later: key-v4l-01HAAA auto-purged by Redis TTL)
```

### Zero-downtime guarantee

During verification, the server always tries:
1. Active key first
2. If MAC fails — check the token's footer `kid` field
3. If `kid` matches a retired key still within grace period — try that key
4. If all fail — `TOKEN_INVALID`

Users are never logged out during a standard rotation.

---

## Redis Storage Schema

```
# Active key — one per purpose per tenant
vaulttoken:keys:{tenant}:{purpose}:active
Value: JSON {
  id:        "key-v4l-01HBBB",
  version:   "v4",
  purpose:   "local",
  key:       "<base64(iv || tag || AES-GCM-ciphertext)>",
  createdAt: "2025-01-15T00:00:00Z",
  tenant:    "default"
}

# Retired key — one entry per retired key, auto-expires
vaulttoken:keys:{tenant}:{purpose}:retired:{keyId}
Value: JSON {
  ...same fields...,
  retiredAt: "2025-01-15T10:00:00Z",
  expiresAt: "2025-01-16T10:00:00Z"
}
TTL: = gracePeriod seconds

# Public key data (cleartext — safe to expose)
vaulttoken:keys:{tenant}:public:{keyId}
Value: JSON {
  id:        "key-v4p-01HYYY",
  publicKey: "<base64url 32-byte Ed25519 public key>",
  createdAt: "2025-01-15T00:00:00Z"
}

# Public keys index (for GET /keys endpoint)
vaulttoken:keys:{tenant}:public:index
Type: Redis Set
Members: [ "key-v4p-01HYYY", "key-v4p-01HZZZ" ]

# Emergency blocklist
vaulttoken:keys:blocked
Type: Redis Set
Members: [ "key-v4l-01HXXX" ]
```

---

## Key Encryption at Rest

All key material is encrypted before writing to Redis.

**Encryption:**
```
iv          = crypto.randomBytes(12)          // 96-bit IV for AES-GCM
cipher      = AES-256-GCM(KEY_ENCRYPTION_SECRET, iv)
ciphertext  = cipher.encrypt(rawKeyBytes)
tag         = cipher.getAuthTag()             // 128-bit authentication tag
stored      = base64( iv || tag || ciphertext )
```

**Decryption:**
```
buf         = base64decode(stored)
iv          = buf.slice(0, 12)
tag         = buf.slice(12, 28)
ciphertext  = buf.slice(28)
decipher    = AES-256-GCM(KEY_ENCRYPTION_SECRET, iv)
decipher.setAuthTag(tag)
rawKeyBytes = decipher.decrypt(ciphertext)
```

If `KEY_ENCRYPTION_SECRET` is wrong, the GCM authentication tag check fails and decryption throws. No partial plaintext is ever returned.

---

## Public Key Endpoint

For `v4.public` tokens, external verifiers need the public key. VaultToken exposes it at:

```
GET /keys
```

**Properties:**
- No authentication required — public keys are safe to share
- JWKS-style response (`kty`, `crv`, `use`, `alg`, `x`, `kid`)
- Returns both active and retired public keys (needed for grace-period verification)
- Cache aggressively — 10-minute TTL is safe; invalidate on rotation webhooks

---

## Multi-Tenant Key Isolation

Each tenant has a completely separate key namespace:

```
Tenant "acme-corp":
  vaulttoken:keys:acme-corp:local:active
  vaulttoken:keys:acme-corp:local:retired:*
  vaulttoken:keys:acme-corp:public:*

Tenant "globex":
  vaulttoken:keys:globex:local:active
  vaulttoken:keys:globex:local:retired:*
```

A token encrypted with `acme-corp`'s key will always fail the AEAD MAC when verified under `globex`'s key. Cross-tenant acceptance is impossible.

---

## Emergency Key Revocation

Use when you believe a key has been compromised:

```bash
npm run revoke -- --key key-v4l-01HAAA --type local
```

**What this does:**
1. Deletes the key from active and retired stores immediately — no grace period
2. Adds the key ID to `vaulttoken:keys:blocked` (permanent Redis Set)
3. Any future verification that presents a token with `kid: "key-v4l-01HAAA"` in its footer is rejected before decryption is attempted
4. Emits a `key.emergency_revoked` audit log entry

**Warning:** All users whose tokens were issued with the compromised key will be immediately logged out. Coordinate with your team before running this in production.

---

## Automated Rotation

Schedule via cron or a built-in interval:

```bash
# crontab — rotate local key every 30 days at 3am UTC
0 3 1 * * cd /opt/vaulttoken && npm run rotate -- --type local --yes
```

Or set in `.env` for the built-in scheduler:
```env
KEY_AUTO_ROTATE=true
KEY_AUTO_ROTATE_INTERVAL=2592000    # 30 days in seconds
KEY_AUTO_ROTATE_GRACE=86400         # 24h grace period
KEY_ROTATION_WEBHOOK=https://alerts.yourcompany.com/hooks/vaulttoken
```

Rotation events are logged to the audit log and optionally POST'd to a webhook URL.

---

## File-Based Key Storage (development only)

For environments without Redis:

```env
KEY_STORAGE=file
KEY_FILE_PATH=./keys/keystore.json
```

The file is encrypted identically to Redis storage. **Never commit this file.**

```
# .gitignore
/keys/
*.keystore.json
```
