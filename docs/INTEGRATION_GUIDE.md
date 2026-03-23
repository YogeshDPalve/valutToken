# Integration Guide: Using VaultToken

VaultToken is a **Secure Token Service (STS)**. Unlike `jsonwebtoken`, which is a library that runs *inside* your application, VaultToken runs as a **standalone microservice** (Sidecar or Centralized).

This architecture provides several benefits:
- **Centralized Key Management**: No need to distribute secrets/private keys to every microservice.
- **Instant Revocation**: Tokens can be revoked globally via Redis.
- **Built-in Audit Logs**: Every issue/verify/refresh event is logged.
- **Algorithm Security**: Uses PASETO v4 (Ed25519/XChaCha20), which is immune to many JWT vulnerabilities like `alg: none`.

---

## 1. Concepts Mapping

If you are used to `jsonwebtoken`, here is how the concepts map to VaultToken:

| Concept | `jsonwebtoken` (Library) | VaultToken (API) |
| :--- | :--- | :--- |
| **Sign / Issue** | `jwt.sign(payload, secret)` | `POST /tokens/issue` |
| **Verify** | `jwt.verify(token, secret)` | `POST /tokens/verify` |
| **Decode** | `jwt.decode(token)` | `POST /tokens/introspect` or `/verify` |
| **Refresh** | Manual implementation | `POST /tokens/refresh` (Native support) |
| **Revoke** | Hard to do (Blacklisting) | `POST /tokens/revoke` (Built-in) |

---

## 2. Using it like a Library (Client Wrapper)

You can create a simple wrapper in your application to make it feel like `jsonwebtoken`. 

### JavaScript Example (Node.js)

```javascript
const axios = require('axios');

class VaultClient {
  constructor({ baseUrl, apiKey }) {
    this.client = axios.create({
      baseURL: baseUrl,
      headers: { 'X-API-Key': apiKey }
    });
  }

  /**
   * Equivalent to jwt.sign()
   */
  async sign(claims, options = {}) {
    const res = await this.client.post('/tokens/issue', {
      ...claims,
      ...options
    });
    return res.data; // { token, refreshToken }
  }

  /**
   * Equivalent to jwt.verify()
   */
  async verify(token, implicitAssertion = null) {
    try {
      const res = await this.client.post('/tokens/verify', {
        token,
        implicitAssertion
      });
      return res.data.claims; // Returns decoded claims if valid
    } catch (err) {
      throw new Error(err.response?.data?.error || 'TOKEN_INVALID');
    }
  }

  /**
   * Equivalent to jwt.decode()
   * Note: In PASETO v4.local, tokens are encrypted. 
   * You MUST use /verify or /introspect to see the payload.
   */
  async decode(token) {
    const res = await this.client.post('/tokens/introspect', { token });
    return res.data.claims;
  }
}

// Usage
const vault = new VaultClient({ 
  baseUrl: 'http://localhost:3000', 
  apiKey: 'your-tenant-api-key' 
});

const { token } = await vault.sign({ sub: 'user_123', role: 'admin' });
const claims = await vault.verify(token);
```

---

## 3. Why is there no `jwt.decode` for everything?

In `jsonwebtoken`, anyone can decode a JWT because it is only Base64 encoded. In VaultToken:

1. **`v4.local` (Local Tokens)**: These are **Authenticated Encryption** (AEAD). The payload is encrypted. Only the VaultToken server (which holds the key) can see the contents. This prevents sensitive data in the claims from being leaked to the client.
2. **`v4.public` (Public Tokens)**: These are signed but not encrypted. You can decode them, but for security, it is always recommended to let the server handle the verification to ensure the signature is valid.

## 4. Middleware Integration (Express)

```javascript
const protect = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const claims = await vault.verify(token);
    req.user = claims; // Attach claims to request
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};
```
