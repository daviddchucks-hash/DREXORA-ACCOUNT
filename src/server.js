const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const config = require('./config');
const { globalRateLimiter } = require('./middleware/auth.middleware');

const authRoutes = require('./routes/auth.routes');
const accountRoutes = require('./routes/account.routes');

const app = express();

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: config.appUrl,
  credentials: true
}));

// Global rate limiting
app.use(globalRateLimiter);

// Body and Cookie Parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser(config.session.secret));

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// Health check endpoint for Render / Uptime checks
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/account', accountRoutes);

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

// Fallback to index.html for SPA client navigation (Express 4.21 compatibility)
app.use((req, res) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, '../public/index.html'));
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
