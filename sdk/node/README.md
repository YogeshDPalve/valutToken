# VaultToken Node SDK

A lightweight client for interacting with the [VaultToken](https://github.com/YogeshDPalve/valutToken) PASETO service.

## Installation

```bash
# From local directory during development
npm install ../path-to-this-repo/sdk/node

# Future usage once published
# npm install vault-token-node
```

## Usage

```javascript
const VaultClient = require('vault-token-node');

const vault = new VaultClient({
  baseUrl: 'http://localhost:3000',
  apiKey: 'your-tenant-api-key'
});

// 1. Issue a token (Sign)
const { token, refreshToken } = await vault.sign({ 
  sub: 'user_123', 
  role: 'admin' 
});

// 2. Verify a token
try {
  const claims = await vault.verify(token);
  console.log('Login successful for:', claims.sub);
} catch (err) {
  console.error('Invalid token:', err.message);
}

// 3. Introspect (Decode)
const info = await vault.decode(token);
if (info.active) {
  console.log('Token is still valid');
}
```

## API Reference

### `new VaultClient({ baseUrl, apiKey })`
Initializes the client.

### `client.sign(claims, [options])`
Issues a token. Options include:
- `purpose`: 'local' (default) or 'public'
- `ttl`: Seconds until expiration
- `issueRefresh`: Boolean

### `client.verify(token, [implicitAssertion])`
Verifies token signature and expiration.

### `client.decode(token)`
Checks token status (active/inactive) and returns claims if available.

### `client.refresh(refreshToken)`
Rotates a refresh token for a new access/refresh pair.
