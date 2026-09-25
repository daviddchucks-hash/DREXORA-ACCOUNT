const oauthService = require('../services/oauth.service');
const sessionService = require('../services/session.service');
const userService = require('../services/user.service');
const config = require('../config');

class OAuthController {
  /**
   * OAuth 2.0 / OIDC Authorization Endpoint
   * GET /oauth/authorize
   */
  async authorize(req, res, next) {
    try {
      const clientId = req.query.client_id || req.body.client_id;
      const redirectUri = req.query.redirect_uri || req.body.redirect_uri;
      const responseType = req.query.response_type || req.body.response_type;
      const scope = req.query.scope || req.body.scope || 'openid profile email';
      const state = req.query.state || req.body.state || '';
      const codeChallenge = req.query.code_challenge || req.body.code_challenge;
      const codeChallengeMethod = req.query.code_challenge_method || req.body.code_challenge_method || 'S256';
      const consentAction = req.query.consent || req.body.consent;

      if (!clientId) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'client_id parameter is required' });
      }

      // 1. Validate Client
      const client = await oauthService.getClient(clientId);
      if (!client || client.status !== 'active') {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client application is invalid, disabled, or not found' });
      }

      // 2. Validate Redirect URI
      if (!redirectUri || !oauthService.validateRedirectUri(client, redirectUri)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'The redirect_uri provided is not registered for this client' });
      }

      // Helper function to build redirect error URL
      const redirectWithError = (errCode, errDesc) => {
        const u = new URL(redirectUri);
        u.searchParams.set('error', errCode);
        if (errDesc) u.searchParams.set('error_description', errDesc);
        if (state) u.searchParams.set('state', state);
        return res.redirect(u.toString());
      };

      // 3. Validate Response Type
      if (responseType !== 'code') {
        return redirectWithError('unsupported_response_type', 'Only response_type=code is supported');
      }

      // 4. Validate Scopes
      let validatedScopes;
      try {
        validatedScopes = oauthService.validateScopes(client, scope);
      } catch (err) {
        return redirectWithError(err.error || 'invalid_scope', err.error_description || 'Invalid requested scope');
      }

      // 5. Enforce PKCE for Public Clients
      if (client.clientType === 'public' && !codeChallenge) {
        return redirectWithError('invalid_request', 'code_challenge parameter is required for public clients');
      }

      // 6. Check Authentication Session
      const rawSessionId = req.cookies[config.session.cookieName] || parseBearerToken(req);
      const session = rawSessionId ? await sessionService.getValidSession(rawSessionId) : null;

      if (!session) {
        // Redirect user to login with return_to pointing back to full authorize request
        const returnUrl = req.originalUrl || `/oauth/authorize?${new URLSearchParams(req.query).toString()}`;
        return res.redirect(`/login.html?return_to=${encodeURIComponent(returnUrl)}`);
      }

      // 7. Check User Account Status
      const user = await userService.findByUserId(session.drexoraUserId);
      if (!user) {
        return res.redirect(`/login.html?error=account_not_found`);
      }

      if (user.accountStatus === 'email_unverified' || !user.emailVerified) {
        return res.redirect(`/verify-email.html?notice=email_verification_required`);
      }

      if (user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
        return redirectWithError('access_denied', `Your account is ${user.accountStatus}`);
      }

      // 8. Handle Consent
      if (consentAction === 'approved') {
        await oauthService.recordUserConsent(user.drexoraUserId, client.clientId, validatedScopes);
        const code = await oauthService.createAuthorizationCode({
          clientId: client.clientId,
          drexoraUserId: user.drexoraUserId,
          redirectUri,
          scope: validatedScopes,
          codeChallenge,
          codeChallengeMethod
        });

        const successUrl = new URL(redirectUri);
        successUrl.searchParams.set('code', code);
        if (state) successUrl.searchParams.set('state', state);
        return res.redirect(successUrl.toString());
      }

      if (consentAction === 'denied') {
        return redirectWithError('access_denied', 'User denied authorization request');
      }

      // Check if user has already granted consent
      const hasConsented = await oauthService.hasUserConsented(user.drexoraUserId, client.clientId, validatedScopes);
      if (hasConsented && req.query.prompt !== 'consent') {
        const code = await oauthService.createAuthorizationCode({
          clientId: client.clientId,
          drexoraUserId: user.drexoraUserId,
          redirectUri,
          scope: validatedScopes,
          codeChallenge,
          codeChallengeMethod
        });

        const successUrl = new URL(redirectUri);
        successUrl.searchParams.set('code', code);
        if (state) successUrl.searchParams.set('state', state);
        return res.redirect(successUrl.toString());
      }

      // Show Consent Screen
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const consentPageUrl = new URL('/oauth-consent.html', baseUrl);
      consentPageUrl.searchParams.set('client_id', client.clientId);
      consentPageUrl.searchParams.set('redirect_uri', redirectUri);
      consentPageUrl.searchParams.set('response_type', 'code');
      consentPageUrl.searchParams.set('scope', validatedScopes.join(' '));
      if (state) consentPageUrl.searchParams.set('state', state);
      if (codeChallenge) consentPageUrl.searchParams.set('code_challenge', codeChallenge);
      if (codeChallengeMethod) consentPageUrl.searchParams.set('code_challenge_method', codeChallengeMethod);

      return res.redirect(consentPageUrl.toString());
    } catch (error) {
      next(error);
    }
  }

  /**
   * Endpoint to fetch client details for consent UI
   * GET /oauth/consent-info
   */
  async getConsentInfo(req, res, next) {
    try {
      const clientId = req.query.client_id;
      const scope = req.query.scope || 'openid profile email';

      if (!clientId) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'client_id is required' });
      }

      const client = await oauthService.getClient(clientId);
      if (!client || client.status !== 'active') {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client not found or disabled' });
      }

      const scopeList = scope.split(' ').map(s => s.trim()).filter(Boolean);

      const scopeDescriptions = {
        openid: 'Verify your identity using Drexora Single Sign-On',
        profile: 'Access your full name and public account profile',
        email: 'Access your primary email address and email verification status',
        'profile.read': 'Access your profile name',
        'email.read': 'Access your email address',
        'account.read': 'Access your account basic details'
      };

      const scopesWithDetails = scopeList.map(s => ({
        key: s,
        description: scopeDescriptions[s] || `Permission to access ${s}`
      }));

      res.status(200).json({
        client: {
          clientId: client.clientId,
          name: client.name,
          description: client.description,
          appType: client.appType, // 'drexora_product' | 'external_application'
          clientType: client.clientType,
          owner: client.owner
        },
        scopes: scopesWithDetails,
        user: {
          drexoraUserId: req.user.drexoraUserId,
          fullName: req.user.profile.fullName,
          email: req.user.profile.email
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * OAuth 2.0 Token Endpoint
   * POST /oauth/token
   */
  async token(req, res, next) {
    try {
      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier
      } = req.body;

      if (!grant_type) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'grant_type parameter is required' });
      }

      if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only grant_type=authorization_code is supported' });
      }

      if (!client_id) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'client_id is required' });
      }

      const client = await oauthService.getClient(client_id);
      if (!client || client.status !== 'active') {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client not found or disabled' });
      }

      // Confidential client authentication
      if (client.clientType === 'confidential') {
        if (!client_secret) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'client_secret is required for confidential clients' });
        }
        const { hashToken } = require('../utils/id.generator');
        if (hashToken(client_secret) !== client.clientSecretHash) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
        }
      }

      // Consume Authorization Code (handles single-use & PKCE verification)
      const codeRecord = await oauthService.consumeAuthorizationCode({
        code,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeVerifier: code_verifier,
        clientSecret: client_secret
      });

      // Issue Access & ID Tokens
      const tokenResponse = await oauthService.issueTokens({
        clientId: client_id,
        drexoraUserId: codeRecord.drexoraUserId,
        scope: codeRecord.scope
      });

      // Prevent caching of tokens
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.status(200).json(tokenResponse);
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json({
          error: error.error,
          error_description: error.error_description
        });
      }
      next(error);
    }
  }

  /**
   * OpenID Connect UserInfo Endpoint
   * GET /oauth/userinfo
   */
  async userinfo(req, res, next) {
    try {
      const rawAccessToken = parseBearerToken(req);
      if (!rawAccessToken) {
        res.setHeader('WWW-Authenticate', 'Bearer error="invalid_request", error_description="Access token required in Authorization header"');
        return res.status(401).json({ error: 'invalid_request', error_description: 'Access token required in Authorization header' });
      }

      const userInfo = await oauthService.getUserInfo(rawAccessToken);
      res.status(200).json(userInfo);
    } catch (error) {
      if (error.error) {
        res.setHeader('WWW-Authenticate', `Bearer error="${error.error}", error_description="${error.error_description || ''}"`);
        return res.status(error.status || 401).json({
          error: error.error,
          error_description: error.error_description
        });
      }
      next(error);
    }
  }

  /**
   * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
   * POST /oauth/revoke
   */
  async revoke(req, res, next) {
    try {
      const token = req.body.token || parseBearerToken(req);
      await oauthService.revokeToken(token);
      res.status(200).json({ status: 'success', message: 'Token revoked successfully' });
    } catch (error) {
      res.status(200).json({ status: 'success', message: 'Token revoked successfully' });
    }
  }

  /**
   * Controlled Client Registration Endpoint (Admin / Internal seed)
   * POST /api/admin/clients
   */
  async registerClient(req, res, next) {
    try {
      const registered = await oauthService.registerClient(req.body);
      res.status(201).json({
        message: 'Application registered successfully',
        client: registered
      });
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }
}

function parseBearerToken(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1].trim();
  }
  return null;
}

module.exports = new OAuthController();
