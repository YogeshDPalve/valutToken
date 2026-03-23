#!/usr/bin/env node
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Redis = require('ioredis');
const config = require('../src/config');
const KeyService = require('../src/services/KeyService');

const argv = yargs(hideBin(process.argv))
  .option('tenant', {
    type: 'string',
    description: 'Tenant ID',
    demandOption: true
  })
  .help()
  .argv;

async function run() {
  const redis = new Redis(config.redis.url);
  const keyService = new KeyService(redis, config);

  try {
    const result = await keyService.listKeys(argv.tenant);
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('Error listing keys:', err.message);
  } finally {
    redis.quit();
  }
}

run();
