# 🔐 VaultToken

> **Secure-by-default token infrastructure built on PASETO v4**
> The token server that makes JWT's worst security mistakes impossible.

---

## What is VaultToken?

VaultToken is a production-ready **token issuance, validation, and management server** built on PASETO v4. It replaces JWT-based auth flows with a system where cryptographic mistakes are impossible by design.

---

## Why not JWT?

| Problem | JWT | VaultToken |
|---|---|---|
| Algorithm selection | Developer picks at runtime | Fixed by version — no choice |
| Payload visibility | Base64 only — anyone can read | Fully encrypted (v4.local) |
| alg:none attack | Historically exploited | Impossible — no alg field |
| Key rotation | Manual, error-prone | Built-in, zero-downtime |
| Token revocation | Not in spec | Redis JTI blocklist |
| Refresh token reuse | No standard detection | Token family tracking built-in |
| Implicit assertions | Not supported | Bind tokens to IP / User-Agent |

---

## Project Structure

```
vaulttoken/
├── src/
│   ├── config/               # App config, env validation
│   ├── controllers/          # Route handlers
│   ├── middleware/           # Auth, rate-limit, logging, errors
│   ├── routes/               # Express route definitions
│   ├── services/
│   │   ├── TokenService      # PASETO v4 issue / verify
│   │   ├── KeyService        # Key lifecycle, rotation, storage
│   │   ├── RevocationService # JTI blocklist, token families
│   │   └── AuditService      # Structured audit log
│   ├── utils/                # PAE encoding, errors, logger
│   └── validators/           # Request schema validation (Zod)
├── tests/
│   ├── unit/                 # Service-level tests
│   ├── integration/          # HTTP route tests
│   └── e2e/                  # Full flow tests
├── scripts/
│   ├── keygen.js             # Generate keys CLI
│   ├── rotate.js             # Rotate keys CLI
│   └── revoke.js             # Revoke tokens CLI
├── docs/                     # All documentation ← you are here
├── website/                  # Reference landing page
└── docker-compose.yml
```

---

## Documentation

| File | Description |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, components, data flows, PAE internals |
| [SETUP.md](docs/SETUP.md) | Installation, configuration, Redis, Docker, production checklist |
| [API.md](docs/API.md) | REST API reference — every endpoint with request/response examples |
| [SECURITY.md](docs/SECURITY.md) | Threat model, 10 attack classes, crypto primitives |
| [KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | Key rotation, lifecycle, Redis schema, emergency revocation |
| [TASKS.md](docs/TASKS.md) | Full implementation task checklist with dependencies |

---

## Core Dependencies

```json
{
  "@noble/ciphers": "^0.5.3",
  "@noble/ed25519": "^2.1.0",
  "@noble/hashes": "^1.4.0",
  "express": "^4.18.2",
  "ioredis": "^5.3.2",
  "zod": "^3.22.4",
  "pino": "^8.18.0",
  "ulid": "^2.3.0"
}
```

---

## License

MIT
