const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const config = require('./config');
const { globalRateLimiter } = require('./middleware/auth.middleware');

const authRoutes = require('./routes/auth.routes');
const accountRoutes = require('./routes/account.routes');
const oauthRoutes = require('./routes/oauth.routes');
const developerRoutes = require('./routes/developer.routes');
const platformRoutes = require('./routes/platform.routes');
const oauthController = require('./controllers/oauth.controller');
const oauthService = require('./services/oauth.service');

// Seed test client application for dev/testing
oauthService.seedTestClient().catch(() => {});

const app = express();

app.set('trust proxy', 1);

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

// CORS configuration - strict validation for credentials support
const allowedExactOrigins = [
  config.appUrl,
  config.frontendUrl,
  'https://auth.drexxora.name.ng',
  'https://api.drexxora.name.ng',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (
      allowedExactOrigins.includes(origin) ||
      origin.endsWith('.github.io') ||
      origin.startsWith('http://localhost:') ||
      origin.startsWith('http://127.0.0.1:')
    ) {
      return callback(null, origin);
    }
    return callback(new Error('CORS policy: Request origin not allowed'));
  },
  credentials: true
}));

// Global rate limiting
app.use(globalRateLimiter);

// Body and Cookie Parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser(config.session.secret));

const fs = require('fs');
const rootPath = path.join(__dirname, '..');

// Clean URLs Redirect Middleware: Redirect requests ending with .html to clean URLs
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return next();
  }

  if (req.path.endsWith('.html')) {
    let cleanPath = req.path.slice(0, -5);
    if (cleanPath.endsWith('/index')) {
      cleanPath = cleanPath.slice(0, -6) || '/';
    }

    const targetFile = path.join(rootPath, req.path);
    if (fs.existsSync(targetFile) && fs.statSync(targetFile).isFile()) {
      const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
      return res.redirect(301, cleanPath + query);
    }
  }

  next();
});

// Clean URLs Resolution Middleware: Serve .html files for extensionless routes
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return next();
  }

  if (
    req.path.startsWith('/api/') ||
    req.path.startsWith('/oauth') ||
    req.path.startsWith('/.well-known/') ||
    req.path === '/health'
  ) {
    return next();
  }

  const htmlFilePath = path.join(rootPath, `${req.path}.html`);
  if (fs.existsSync(htmlFilePath) && fs.statSync(htmlFilePath).isFile()) {
    return res.sendFile(htmlFilePath);
  }

  if (req.path.startsWith('/public/')) {
    const subPath = req.path.slice(7);
    const publicHtmlPath = path.join(rootPath, `${subPath}.html`);
    if (fs.existsSync(publicHtmlPath) && fs.statSync(publicHtmlPath).isFile()) {
      return res.sendFile(publicHtmlPath);
    }
  }

  next();
});

// Serve static frontend files from repository root AND provide /public alias compatibility
app.use(express.static(rootPath));
app.use('/public', express.static(rootPath));

// Health check endpoint for Render / Uptime checks
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// OpenID Connect Discovery & JWKS
app.get('/.well-known/openid-configuration', oauthController.getOpenIdConfiguration);
app.get('/.well-known/jwks.json', oauthController.getJwks);

// API & OAuth Routes
app.use('/oauth', oauthRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/account', accountRoutes);
app.use('/api/developer', developerRoutes);
app.use('/api/platform', platformRoutes);
app.post('/api/admin/clients', oauthController.registerClient);

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'An unexpected internal server error occurred.';

  if (config.nodeEnv !== 'test' && status === 500) {
    console.error('[Unhandled Error]', err);
  }

  res.status(status).json({
    error: message,
    code: err.code || undefined
  });
});

// Fallback to index.html for SPA client navigation
app.use((req, res) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(rootPath, 'index.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

const PORT = config.port;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[Drexora Account] Server running on port ${PORT} (${config.nodeEnv})`);
  });
}

module.exports = app;
