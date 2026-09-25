require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  appUrl: process.env.APP_URL || 'https://drexora-account.onrender.com',
  frontendUrl: process.env.FRONTEND_URL || process.env.APP_URL || 'https://drexora-account.onrender.com',
  session: {
    secret: process.env.SESSION_SECRET || 'drexora_default_dev_session_secret_change_me',
    maxAgeDays: parseInt(process.env.SESSION_MAX_AGE_DAYS || '14', 10),
    cookieName: 'drexora_sid'
  },
  jwtSecret: process.env.TOKEN_SIGNING_SECRET || process.env.SESSION_SECRET || 'drexora_default_jwt_signing_secret_key',
  firebase: {
    databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://drexora-account-default-rtdb.firebaseio.com',
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined
  },
  resend: {
    apiKey: process.env.RESEND_API_KEY,
    from: process.env.EMAIL_FROM || 'Drexora Account <no-reply@drexxora.name.ng>'
  },
  security: {
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    loginMaxAttempts: parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '10', 10)
  }
};
