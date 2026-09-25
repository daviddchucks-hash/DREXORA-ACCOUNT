const rateLimit = require('express-rate-limit');
const config = require('../config');
const sessionService = require('../services/session.service');
const userService = require('../services/user.service');

const isTestEnv = process.env.NODE_ENV === 'test';

// Global rate limiter
const globalRateLimiter = rateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: isTestEnv ? 1000 : config.security.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Strict rate limiter for sensitive auth endpoints
const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isTestEnv ? 100 : config.security.loginMaxAttempts,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts from this IP, please try again after 15 minutes.' }
});

/**
 * Dynamic Cookie Options Helper
 * Detects whether request is running under HTTPS / Render proxy / Cross-Site
 */
function cookieOptions(req) {
  const isProduction = config.nodeEnv === 'production';
  const isHttps = req ? (req.secure || req.headers['x-forwarded-proto'] === 'https') : isProduction;

  return {
    httpOnly: true,
    secure: isHttps || isProduction,
    sameSite: (isHttps || isProduction) ? 'none' : 'lax',
    path: '/',
    maxAge: config.session.maxAgeDays * 24 * 60 * 60 * 1000
  };
}

/**
 * Cookie Options Helper for clearing cookies
 */
function clearCookieOptions(req) {
  const isProduction = config.nodeEnv === 'production';
  const isHttps = req ? (req.secure || req.headers['x-forwarded-proto'] === 'https') : isProduction;

  return {
    httpOnly: true,
    secure: isHttps || isProduction,
    sameSite: (isHttps || isProduction) ? 'none' : 'lax',
    path: '/'
  };
}

/**
 * Authentication Middleware
 * Validates session cookie or Bearer token and attaches user & session to req
 */
async function authenticate(req, res, next) {
  try {
    const rawSessionId = req.cookies[config.session.cookieName] || parseBearerToken(req);

    if (!rawSessionId) {
      return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    const session = await sessionService.getValidSession(rawSessionId);
    if (!session) {
      res.clearCookie(config.session.cookieName, clearCookieOptions(req));
      return res.status(401).json({ error: 'Session expired or invalidated. Please log in again.' });
    }

    const user = await userService.findByUserId(session.drexoraUserId);
    if (!user) {
      return res.status(401).json({ error: 'User account no longer exists.' });
    }

    // Check account status
    if (user.accountStatus === 'suspended') {
      return res.status(403).json({ error: 'Your account has been suspended. Access denied.' });
    }

    if (user.accountStatus === 'disabled') {
      return res.status(403).json({ error: 'Your account has been disabled. Access denied.' });
    }

    req.user = user;
    req.session = session;
    req.rawSessionId = rawSessionId;
    next();
  } catch (error) {
    console.error('[Auth Middleware Error]', error);
    res.status(500).json({ error: 'Internal security authentication error.' });
  }
}

function parseBearerToken(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1].trim();
  }
  return null;
}

module.exports = {
  globalRateLimiter,
  strictAuthLimiter,
  authenticate,
  cookieOptions,
  clearCookieOptions
};
