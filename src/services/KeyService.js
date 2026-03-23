const crypto = require('crypto');
const { ulid } = require('ulid');
const ed25519 = require('@noble/ed25519');
const { sha512 } = require('@noble/hashes/sha512');
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
const { InternalError, KeyDecryptionError } = require('../utils/errors');
const logger = require('../utils/logger');

class KeyService {
  constructor(redis, config) {
    this.redis = redis;
    this.config = config;
    this.prefix = config.redis.prefix;
    this.masterSecret = config.keys.encryptionSecret; // 32 byte buffer
  }

  _makeKeyId(purpose) {
    const prefix = purpose === 'local' ? 'l' : 'p';
    return `key-v4${prefix}-${ulid()}`;
  }

  _encryptMaterial(rawBytes) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterSecret, iv);
    
    let ciphertext = cipher.update(rawBytes);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();
    
    // Store as base64(iv || tag || ciphertext)
    const combined = Buffer.concat([iv, tag, ciphertext]);
    return combined.toString('base64');
  }

  _decryptMaterial(storedBase64) {
    try {
      const buf = Buffer.from(storedBase64, 'base64');
      const iv = buf.subarray(0, 12);
      const tag = buf.subarray(12, 28);
      const ciphertext = buf.subarray(28);
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterSecret, iv);
      decipher.setAuthTag(tag);
      
      let plaintext = decipher.update(ciphertext);
      plaintext = Buffer.concat([plaintext, decipher.final()]);
      
      return plaintext;
    } catch (err) {
      throw new KeyDecryptionError();
    }
  }

  async generateLocalKey({ tenant }) {
    const rawKey = crypto.randomBytes(32);
    const encrypted = this._encryptMaterial(rawKey);
    const id = this._makeKeyId('local');
    
    const record = {
      id,
      version: 'v4',
      purpose: 'local',
      key: encrypted,
      createdAt: new Date().toISOString(),
      tenant,
    };
    
    const activeKeyPath = `${this.prefix}keys:${tenant}:local:active`;
    
    // Retire existing active key if any
    await this._retireExistingActive(tenant, 'local');
    
    // Set new active key
    await this.redis.set(activeKeyPath, JSON.stringify(record));
    
    return { id, tenant, createdAt: record.createdAt };
  }

  async generatePublicKey({ tenant }) {
    const secretKey = ed25519.utils.randomPrivateKey(); // 32 bytes
    const publicKey = ed25519.getPublicKey(secretKey);  // 32 bytes
    
    const encryptedSecret = this._encryptMaterial(Buffer.from(secretKey));
    const id = this._makeKeyId('public');
    
    const record = {
      id,
      version: 'v4',
      purpose: 'public',
      key: encryptedSecret, // we store the secret key encrypted
      createdAt: new Date().toISOString(),
      tenant,
    };
    
    const activeKeyPath = `${this.prefix}keys:${tenant}:public:active`;
    
    await this._retireExistingActive(tenant, 'public');
    
    // Set new active key
    await this.redis.set(activeKeyPath, JSON.stringify(record));
    
    // Store public key in index
    const pubRecord = {
      id,
      publicKey: Buffer.from(publicKey).toString('base64url'),
      createdAt: record.createdAt,
    };
    
    await this.redis.set(`${this.prefix}keys:${tenant}:public:${id}`, JSON.stringify(pubRecord));
    await this.redis.sadd(`${this.prefix}keys:${tenant}:public:index`, id);
    
    return { id, publicKey: pubRecord.publicKey, tenant, createdAt: record.createdAt };
  }

  async getActiveKey(tenant, purpose) {
    const activeKeyPath = `${this.prefix}keys:${tenant}:${purpose}:active`;
    const data = await this.redis.get(activeKeyPath);
    
    if (!data) return null;
    
    const record = JSON.parse(data);
    const rawKey = this._decryptMaterial(record.key);
    
    let result = {
      id: record.id,
      purpose: record.purpose,
      rawKey,
    };
    
    if (purpose === 'public') {
      const pubData = await this.redis.get(`${this.prefix}keys:${tenant}:public:${record.id}`);
      if (pubData) {
        result.publicKey = Buffer.from(JSON.parse(pubData).publicKey, 'base64url');
      }
    }
    
    return result;
  }

  async getCandidateKeys(tenant, purpose) {
    const candidates = [];
    
    // 1. Get Active
    const active = await this.getActiveKey(tenant, purpose);
    if (active) candidates.push(active);
    
    // 2. Scan for Retired keys
    const pattern = `${this.prefix}keys:${tenant}:${purpose}:retired:*`;
    const keys = await this.redis.keys(pattern);
    
    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const record = JSON.parse(data);
        const rawKey = this._decryptMaterial(record.key);
        
        let candidate = {
          id: record.id,
          purpose: record.purpose,
          rawKey,
        };
        
        if (purpose === 'public') {
          const pubData = await this.redis.get(`${this.prefix}keys:${tenant}:public:${record.id}`);
          if (pubData) {
            candidate.publicKey = Buffer.from(JSON.parse(pubData).publicKey, 'base64url');
          }
        }
        
        candidates.push(candidate);
      }
    }
    
    return candidates;
  }

  async getKeyById(tenant, purpose, keyId) {
    const candidates = await this.getCandidateKeys(tenant, purpose);
    return candidates.find(k => k.id === keyId) || null;
  }

  async rotateKey(tenant, purpose, gracePeriodSecs) {
    const activeKeyPath = `${this.prefix}keys:${tenant}:${purpose}:active`;
    const activeData = await this.redis.get(activeKeyPath);
    
    let retiredKeyId = null;
    if (activeData) {
      const record = JSON.parse(activeData);
      retiredKeyId = record.id;
    }
    
    let newKey;
    if (purpose === 'local') {
       newKey = await this.generateLocalKey({ tenant });
    } else {
       newKey = await this.generatePublicKey({ tenant });
    }
    
    const gracePeriod = gracePeriodSecs ?? this.config.keys.rotationGracePeriod;
    const gracePeriodEndsAt = new Date(Date.now() + gracePeriod * 1000).toISOString();
    
    return {
      newKeyId: newKey.id,
      retiredKeyId,
      gracePeriodEndsAt,
    };
  }

  async _retireExistingActive(tenant, purpose) {
    const activeKeyPath = `${this.prefix}keys:${tenant}:${purpose}:active`;
    const activeData = await this.redis.get(activeKeyPath);
    
    if (activeData) {
      const record = JSON.parse(activeData);
      const gracePeriod = this.config.keys.rotationGracePeriod;
      
      const retiredRecord = {
        ...record,
        retiredAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + gracePeriod * 1000).toISOString(),
      };
      
      const retiredKeyPath = `${this.prefix}keys:${tenant}:${purpose}:retired:${record.id}`;
      await this.redis.set(retiredKeyPath, JSON.stringify(retiredRecord), 'EX', gracePeriod);
      await this.redis.del(activeKeyPath);
    }
  }

  async getPublicKeys(tenant) {
    const indexKey = `${this.prefix}keys:${tenant}:public:index`;
    const keyIds = await this.redis.smembers(indexKey);
    
    const keys = [];
    for (const id of keyIds) {
      const data = await this.redis.get(`${this.prefix}keys:${tenant}:public:${id}`);
      if (data) {
        const parsed = JSON.parse(data);
        keys.push({
          kid: parsed.id,
          kty: 'OKP',
          crv: 'Ed25519',
          use: 'sig',
          alg: 'EdDSA',
          x: parsed.publicKey,
          createdAt: parsed.createdAt,
        });
      }
    }
    
    return keys;
  }

  async listKeys(tenant) {
    // Return metadata (no materials)
    const lists = { active: [], retired: [] };
    
    for (const purpose of ['local', 'public']) {
      const activeData = await this.redis.get(`${this.prefix}keys:${tenant}:${purpose}:active`);
      if (activeData) {
        const record = JSON.parse(activeData);
        delete record.key;
        lists.active.push(record);
      }
      
      const pattern = `${this.prefix}keys:${tenant}:${purpose}:retired:*`;
      const keys = await this.redis.keys(pattern);
      
      for (const key of keys) {
        const data = await this.redis.get(key);
        if (data) {
          const record = JSON.parse(data);
          delete record.key;
          lists.retired.push(record);
        }
      }
    }
    
    return lists;
  }

  async emergencyRevokeKey(tenant, purpose, keyId) {
    // Delete from active or retired
    const activeKeyPath = `${this.prefix}keys:${tenant}:${purpose}:active`;
    const activeData = await this.redis.get(activeKeyPath);
    if (activeData) {
        const parsed = JSON.parse(activeData);
        if (parsed.id === keyId) await this.redis.del(activeKeyPath);
    }
    
    const retiredKeyPath = `${this.prefix}keys:${tenant}:${purpose}:retired:${keyId}`;
    await this.redis.del(retiredKeyPath);
    
    // Add to blocked set permanently
    await this.redis.sadd(`${this.prefix}keys:blocked`, keyId);
  }

  async isKeyBlocked(keyId) {
    const isBlocked = await this.redis.sismember(`${this.prefix}keys:blocked`, keyId);
    return isBlocked === 1;
  }
}

module.exports = KeyService;
