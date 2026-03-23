const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');
const logger = require('./utils/logger');
const securityHeaders = require('./middleware/securityHeaders');
const errorHandler = require('./middleware/errorHandler');
const { auth } = require('./middleware/auth');

const KeyService = require('./services/KeyService');
const TokenService = require('./services/TokenService');
const RevocationService = require('./services/RevocationService');
const AuditService = require('./services/AuditService');

const KeyController = require('./controllers/KeyController');
const TokenController = require('./controllers/TokenController');
const AdminController = require('./controllers/AdminController');

const createTokenRoutes = require('./routes/tokens');
const createKeyRoutes = require('./routes/keys');
const createAdminRoutes = require('./routes/admin');

function createApp(redisClient) {
  const app = express();

  // Instantiate services
  const keyService = new KeyService(redisClient, config);
  const tokenService = new TokenService(config);
  const revocationService = new RevocationService(redisClient, config);
  const auditService = new AuditService(redisClient, config);

  // Instantiate controllers
  const keyController = new KeyController(keyService, auditService);
  const tokenController = new TokenController(tokenService, keyService, revocationService, auditService);
  const adminController = new AdminController(auditService, keyService, revocationService);

  app.set('trust proxy', 1);

  // 1. Security Headers
  app.use(securityHeaders());

  // 2. CORS
  app.use(cors());

  // 3. Body Parser
  app.use(express.json({ limit: '100kb' }));

  // 4. Correlation ID & Logger
  app.use((req, res, next) => {
    req.id = uuidv4();
    res.setHeader('X-Request-Id', req.id);
    next();
  });

  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const ms = Date.now() - start;
      logger.info({
        reqId: req.id,
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        duration: ms,
        ip: req.ip
      }, 'Request processed');
    });
    next();
  });

  // 5. Routes
  app.use('/keys', createKeyRoutes(keyController, config));
  app.use('/admin', createAdminRoutes(adminController, config));
  
  // Tokens require API Key Auth
  app.use('/tokens', auth(config), createTokenRoutes(tokenController, redisClient));

  // 6. 404 Handler
  app.use((req, res) => {
    res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' });
  });

  // 7. Error Handler
  app.use(errorHandler);

  return app;
}

module.exports = createApp;
