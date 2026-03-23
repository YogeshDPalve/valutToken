const Redis = require('ioredis');
const config = require('./config');
const logger = require('./utils/logger');
const createApp = require('./app');

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'Uncaught exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.fatal({ reason, promise }, 'Unhandled rejection');
  process.exit(1);
});

async function start() {
  const redis = new Redis(config.redis.url, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      if (times > 10) {
        logger.fatal('Redis connection failed after 10 retries, exiting');
        process.exit(1);
        return null; // Stop retrying
      }
      return Math.min(times * 100, 3000);
    }
  });

  redis.on('error', (err) => logger.error({ err }, 'Redis connection error'));
  redis.on('connect', () => logger.info('Connected to Redis'));

  const app = createApp(redis);

  const server = app.listen(config.port, config.host, () => {
    logger.info(`VaultToken Server listening on http://${config.host}:${config.port}`);
  });

  // Graceful shutdown
  const shutdown = async (signal) => {
    logger.info({ signal }, 'Received kill signal, shutting down gracefully');
    
    server.close(async () => {
      logger.info('HTTP server closed');
      await redis.quit();
      logger.info('Redis connection closed');
      process.exit(0);
    });

    // Force close after 10s
    setTimeout(() => {
      logger.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch(err => {
  logger.fatal({ err }, 'Failed to start server');
  process.exit(1);
});
