#!/usr/bin/env node
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Redis = require('ioredis');
const config = require('../src/config');
const KeyService = require('../src/services/KeyService');
const readline = require('readline');

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
  .option('grace', {
    type: 'number',
    description: 'Grace period in seconds for the retired key',
    default: 86400
  })
  .option('yes', {
    alias: 'y',
    type: 'boolean',
    description: 'Skip confirmation prompt'
  })
  .help()
  .argv;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function run() {
  const isProd = process.env.NODE_ENV === 'production';
  
  if (isProd && !argv.yes) {
    const answer = await new Promise(resolve => {
      rl.question(`WARNING: You are about to rotate the active ${argv.type} key for tenant '${argv.tenant}' in PRODUCTION. Continue? (y/N) `, resolve);
    });
    if (answer.toLowerCase() !== 'y') {
      console.log('Aborted.');
      process.exit(0);
    }
  }

  const redis = new Redis(config.redis.url);
  const keyService = new KeyService(redis, config);

  try {
    const result = await keyService.rotateKey(argv.tenant, argv.type, argv.grace);
    console.log('Successfully rotated key:');
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('Error rotating key:', err.message);
  } finally {
    redis.quit();
    rl.close();
  }
}

run();
