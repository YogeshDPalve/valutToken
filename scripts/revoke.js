#!/usr/bin/env node
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Redis = require('ioredis');
const config = require('../src/config');
const KeyService = require('../src/services/KeyService');
const RevocationService = require('../src/services/RevocationService');

const argv = yargs(hideBin(process.argv))
  .option('tenant', {
    type: 'string',
    description: 'Tenant ID',
    demandOption: true
  })
  .option('jti', { type: 'string', description: 'Revoke by JTI' })
  .option('sub', { type: 'string', description: 'Revoke all tokens for subject' })
  .option('family', { type: 'string', description: 'Revoke a specific token family' })
  .option('key', { type: 'string', description: 'Emergency block a specific key ID' })
  .option('purpose', { type: 'string', choices: ['local', 'public'], description: 'Required if revoking by key' })
  .conflicts('jti', ['sub', 'family', 'key'])
  .conflicts('sub', ['jti', 'family', 'key'])
  .conflicts('family', ['jti', 'sub', 'key'])
  .conflicts('key', ['jti', 'sub', 'family'])
  .help()
  .argv;

async function run() {
  if (!argv.jti && !argv.sub && !argv.family && !argv.key) {
    console.error('You must provide one revocation target: --jti, --sub, --family, or --key');
    process.exit(1);
  }

  if (argv.key && !argv.purpose) {
    console.error('You must specify --purpose when revoking an emergency --key');
    process.exit(1);
  }

  const redis = new Redis(config.redis.url);
  const revocationService = new RevocationService(redis, config);
  const keyService = new KeyService(redis, config);

  try {
    if (argv.jti) {
      await revocationService.revoke(argv.jti, argv.tenant, Math.floor(Date.now() / 1000) + 86400 * 30);
      console.log(`Revoked JTI: ${argv.jti}`);
    } else if (argv.sub) {
      await revocationService.revokeBySubject(argv.sub, argv.tenant);
      console.log(`Revoked all tokens for subject: ${argv.sub}`);
    } else if (argv.family) {
      await revocationService.revokeFamily(argv.family, argv.tenant);
      console.log(`Revoked token family: ${argv.family}`);
    } else if (argv.key) {
      await keyService.emergencyRevokeKey(argv.tenant, argv.purpose, argv.key);
      console.log(`Emergency blocked key: ${argv.key}`);
    }
  } catch (err) {
    console.error('Error during revocation:', err.message);
  } finally {
    redis.quit();
  }
}

run();
