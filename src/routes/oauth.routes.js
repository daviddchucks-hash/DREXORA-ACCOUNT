const express = require('express');
const router = express.Router();
const oauthController = require('../controllers/oauth.controller');
const { authenticate, strictAuthLimiter } = require('../middleware/auth.middleware');

// OAuth 2.0 / OIDC Core Endpoints
router.get('/authorize', oauthController.authorize);
router.post('/authorize', oauthController.authorize);

router.get('/consent-info', authenticate, oauthController.getConsentInfo);

router.post('/token', strictAuthLimiter, oauthController.token);

router.get('/userinfo', oauthController.userinfo);

router.post('/revoke', oauthController.revoke);

// OIDC Discovery & JWKS
router.get('/.well-known/openid-configuration', oauthController.getOpenIdConfiguration);
router.get('/.well-known/jwks.json', oauthController.getJwks);

module.exports = router;
