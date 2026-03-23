#!/usr/bin/env node
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Redis = require('ioredis');
const config = require('../src/config');
const AuditService = require('../src/services/AuditService');

const argv = yargs(hideBin(process.argv))
  .option('tenant', {
    type: 'string',
    description: 'Tenant ID',
    demandOption: true
  })
  .option('event', {
    type: 'string',
    description: 'Filter by event type'
  })
  .option('sub', {
    type: 'string',
    description: 'Filter by subject'
  })
  .option('limit', {
    type: 'number',
    description: 'Number of logs to return',
    default: 20
  })
  .help()
  .argv;

async function run() {
  const redis = new Redis(config.redis.url);
  const auditService = new AuditService(redis, config);

  try {
    const logs = await auditService.query(argv);
    console.log(`Found ${logs.length} matching events:`);
    for (const log of logs) {
      console.log(`[${new Date(log.timestamp).toISOString()}] ${log.event} - ${JSON.stringify(log.data)}`);
    }
  } catch (err) {
    console.error('Error tailing audit logs:', err.message);
  } finally {
    redis.quit();
  }
}

run();
