#!/usr/bin/env node
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Redis = require('ioredis');
const config = require('../src/config');
const KeyService = require('../src/services/KeyService');

const argv = yargs(hideBin(process.argv))
  .option('type', {
    alias: 't',
    type: 'string',
    description: 'Type of key (local or public)',
    choices: ['local', 'public'],
    demandOption: true
  })
  .option('tenant', {
    type: 'string',
    description: 'Tenant ID',
    demandOption: true
  })
  .option('show-public', {
    type: 'boolean',
    description: 'Print the raw public key if type is public'
  })
  .help()
  .argv;

async function run() {
  const redis = new Redis(config.redis.url);
  const keyService = new KeyService(redis, config);

  try {
    let result;
    if (argv.type === 'local') {
      result = await keyService.generateLocalKey({ tenant: argv.tenant });
    } else {
      result = await keyService.generatePublicKey({ tenant: argv.tenant });
    }
    
    console.log('Successfully generated key:');
    console.log(JSON.stringify({
      id: result.id,
      tenant: result.tenant,
      createdAt: result.createdAt,
      ...(argv.showPublic && result.publicKey ? { publicKey: result.publicKey } : {})
    }, null, 2));

  } catch (err) {
    console.error('Error generating key:', err.message);
  } finally {
    redis.quit();
  }
}

run();
