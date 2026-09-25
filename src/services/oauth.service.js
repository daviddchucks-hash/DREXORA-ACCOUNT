const db = require('../db/firebase');
const config = require('../config');
const userService = require('./user.service');
const { generateSecureToken, hashToken } = require('../utils/id.generator');
const { signJwt, verifyCodeChallenge } = require('../utils/jwt.util');

const CODE_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes
const ACCESS_TOKEN_EXPIRATION_SECONDS = 3600; // 1 hour

class OAuthService {
  /**
   * Registers a new OAuth client / application in the controlled registry.
   */
  async registerClient({
    clientId,
    clientSecret,
    clientType = 'public', // 'public' | 'confidential'
    appType = 'external_application', // 'drexora_product' | 'external_application'
    name,
    description = '',
    owner = { ownerId: 'system', ownerType: 'developer' },
    redirectUris = [],
    allowedOrigins = [],
    allowedScopes = ['openid', 'profile', 'email'],
    status = 'active'
  }) {
    if (!name || typeof name !== 'string') {
      throw { status: 400, error: 'invalid_request', error_description: 'Application name is required' };
    }

    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw { status: 400, error: 'invalid_request', error_description: 'At least one valid redirect URI is required' };
    }

    const finalClientId = clientId || `dx_client_${generateSecureToken(12)}`;
    let finalClientSecret = null;

    if (clientType === 'confidential') {
      finalClientSecret = clientSecret || `dx_secret_${generateSecureToken(24)}`;
    }

    const now = Date.now();
    const clientRecord = {
      clientId: finalClientId,
      clientSecretHash: finalClientSecret ? hashToken(finalClientSecret) : null,
      clientType,
      appType,
      name: name.trim(),
      description: description ? description.trim() : '',
      owner,
      redirectUris: redirectUris.map(uri => uri.trim()),
      allowedOrigins: allowedOrigins.map(origin => origin.trim()),
      allowedScopes,
      status, // 'active' | 'disabled' | 'pending'
      createdAt: now,
      updatedAt: now
    };

    await db.set(`oauthClients/${finalClientId}`, clientRecord);

    return {
      ...clientRecord,
      clientSecret: finalClientSecret // returned only upon registration
    };
  }

  /**
   * Retrieves a client record by clientId.
   */
  async seedTestClient() {
    try {
      const existing = await this.getClient('dx_client_test_app');
      if (!existing) {
        await this.registerClient({
          clientId: 'dx_client_test_app',
          clientType: 'public',
          appType: 'external_application',
          name: 'Drexora Identity Test App',
          description: 'An independent external test application using Drexora SSO',
          owner: { ownerId: 'dx_system_admin', ownerType: 'developer' },
          redirectUris: [
            'http://localhost:3000/test-client/callback.html',
            'http://127.0.0.1:3000/test-client/callback.html',
            'https://drexora-account.onrender.com/test-client/callback.html'
          ],
          allowedOrigins: [
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'https://drexora-account.onrender.com'
          ],
          allowedScopes: ['openid', 'profile', 'email'],
          status: 'active'
        });
      }
    } catch (err) {
      console.warn('[OAuth Service] Failed to seed default test client:', err.message);
    }
  }

  async getClient(clientId) {
    if (!clientId) return null;
    return await db.get(`oauthClients/${clientId}`);
  }

  /**
   * Validates if target redirect URI is registered for the client.
   * Exact string match required.
   */
  validateRedirectUri(client, redirectUri) {
    if (!client || !client.redirectUris || !redirectUri) return false;
    return client.redirectUris.includes(redirectUri.trim());
  }

  /**
   * Validates requested scopes against client's allowed scopes.
   * Returns array of valid requested scopes.
   */
  validateScopes(client, scopeString) {
    if (!scopeString) return ['openid'];
    const requested = scopeString.split(' ').map(s => s.trim()).filter(Boolean);
    const allowed = client.allowedScopes || ['openid', 'profile', 'email'];

    for (const reqScope of requested) {
      if (!allowed.includes(reqScope)) {
        throw { status: 400, error: 'invalid_scope', error_description: `Scope '${reqScope}' is not allowed for this client` };
      }
    }
    return requested;
  }

  /**
   * Creates a short-lived, single-use authorization code.
   */
  async createAuthorizationCode({ clientId, drexoraUserId, redirectUri, scope, codeChallenge, codeChallengeMethod = 'S256' }) {
    const rawCode = `dx_code_${generateSecureToken(24)}`;
    const codeHash = hashToken(rawCode);
    const now = Date.now();

    const codeData = {
      codeHash,
      clientId,
      drexoraUserId,
      redirectUri,
      scope: Array.isArray(scope) ? scope.join(' ') : scope,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || 'S256',
      used: false,
      expiresAt: now + CODE_EXPIRATION_MS,
      createdAt: now
    };

    await db.set(`oauthAuthorizationCodes/${codeHash}`, codeData);
    return rawCode;
  }

  /**
   * Consumes an authorization code and validates parameters + PKCE.
   * Immediately invalidates code upon exchange to prevent replay.
   */
  async consumeAuthorizationCode({ code, clientId, redirectUri, codeVerifier, clientSecret }) {
    if (!code) {
      throw { status: 400, error: 'invalid_request', error_description: 'Authorization code is required' };
    }

    const codeHash = hashToken(code);
    const codeRecord = await db.get(`oauthAuthorizationCodes/${codeHash}`);

    if (!codeRecord) {
      throw { status: 400, error: 'invalid_grant', error_description: 'Authorization code is invalid or not found' };
    }

    if (codeRecord.used) {
      throw { status: 400, error: 'invalid_grant', error_description: 'Authorization code has already been used' };
    }

    // Immediately mark used
    await db.update(`oauthAuthorizationCodes/${codeHash}`, { used: true, usedAt: Date.now() });

    if (Date.now() > codeRecord.expiresAt) {
      throw { status: 400, error: 'invalid_grant', error_description: 'Authorization code has expired' };
    }

    if (codeRecord.clientId !== clientId) {
      throw { status: 400, error: 'invalid_grant', error_description: 'Authorization code was not issued to this client' };
    }

    if (codeRecord.redirectUri !== redirectUri) {
      throw { status: 400, error: 'invalid_grant', error_description: 'Redirect URI does not match authorization code request' };
    }

    // Validate PKCE if challenge was supplied during authorization
    if (codeRecord.codeChallenge) {
      if (!codeVerifier) {
        throw { status: 400, error: 'invalid_grant', error_description: 'code_verifier is required for PKCE' };
      }
      const isPkceValid = verifyCodeChallenge(codeVerifier, codeRecord.codeChallenge, codeRecord.codeChallengeMethod);
      if (!isPkceValid) {
        throw { status: 400, error: 'invalid_grant', error_description: 'PKCE code_verifier verification failed' };
      }
    }

    return codeRecord;
  }

  /**
   * Issues Access Token and (optional) ID Token for an authenticated user.
   */
  async issueTokens({ clientId, drexoraUserId, scope }) {
    const user = await userService.findByUserId(drexoraUserId);
    if (!user) {
      throw { status: 400, error: 'invalid_grant', error_description: 'User account no longer exists' };
    }

    if (user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
      throw { status: 403, error: 'access_denied', error_description: `User account is ${user.accountStatus}` };
    }

    const rawAccessToken = `dx_at_${generateSecureToken(32)}`;
    const tokenHash = hashToken(rawAccessToken);
    const now = Date.now();

    const scopeList = typeof scope === 'string' ? scope.split(' ').filter(Boolean) : scope;

    const tokenRecord = {
      tokenHash,
      clientId,
      drexoraUserId,
      scope: scopeList.join(' '),
      tokenType: 'Bearer',
      expiresIn: ACCESS_TOKEN_EXPIRATION_SECONDS,
      expiresAt: now + (ACCESS_TOKEN_EXPIRATION_SECONDS * 1000),
      revoked: false,
      createdAt: now
    };

    await db.set(`oauthTokens/${tokenHash}`, tokenRecord);

    const tokenResponse = {
      access_token: rawAccessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_EXPIRATION_SECONDS,
      scope: scopeList.join(' ')
    };

    // If 'openid' scope requested, issue signed OIDC ID Token
    if (scopeList.includes('openid')) {
      const idTokenClaims = {
        iss: config.appUrl,
        sub: user.drexoraUserId, // permanent Drexora User ID
        aud: clientId
      };

      if (scopeList.includes('profile')) {
        idTokenClaims.name = user.profile.fullName;
      }

      if (scopeList.includes('email')) {
        idTokenClaims.email = user.profile.email;
        idTokenClaims.email_verified = user.emailVerified;
      }

      tokenResponse.id_token = signJwt(idTokenClaims, config.jwtSecret, {
        expiresInSeconds: ACCESS_TOKEN_EXPIRATION_SECONDS
      });
    }

    return tokenResponse;
  }

  /**
   * Validates raw access token and returns token record.
   */
  async getValidAccessToken(rawAccessToken) {
    if (!rawAccessToken || typeof rawAccessToken !== 'string') return null;

    const tokenHash = hashToken(rawAccessToken);
    const tokenRecord = await db.get(`oauthTokens/${tokenHash}`);

    if (!tokenRecord || tokenRecord.revoked) return null;

    if (Date.now() > tokenRecord.expiresAt) {
      await db.update(`oauthTokens/${tokenHash}`, { revoked: true, revokedReason: 'expired' });
      return null;
    }

    return tokenRecord;
  }

  /**
   * Retrieves UserInfo profile claims using Bearer access token.
   */
  async getUserInfo(rawAccessToken) {
    const tokenRecord = await this.getValidAccessToken(rawAccessToken);
    if (!tokenRecord) {
      throw { status: 401, error: 'invalid_token', error_description: 'The access token is invalid, expired, or revoked' };
    }

    const user = await userService.findByUserId(tokenRecord.drexoraUserId);
    if (!user) {
      throw { status: 401, error: 'invalid_token', error_description: 'User account not found' };
    }

    if (user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
      throw { status: 403, error: 'access_denied', error_description: `User account is ${user.accountStatus}` };
    }

    const scopeList = (tokenRecord.scope || '').split(' ').filter(Boolean);

    // sub (permanent Drexora User ID) is mandatory for OIDC
    const userInfo = {
      sub: user.drexoraUserId
    };

    if (scopeList.includes('profile') || scopeList.includes('account.read') || scopeList.includes('profile.read')) {
      userInfo.name = user.profile.fullName;
    }

    if (scopeList.includes('email') || scopeList.includes('email.read')) {
      userInfo.email = user.profile.email;
      userInfo.email_verified = user.emailVerified;
    }

    return userInfo;
  }

  /**
   * Revokes an access token (RFC 7009).
   */
  async revokeToken(rawToken) {
    if (!rawToken || typeof rawToken !== 'string') return true;

    const tokenHash = hashToken(rawToken);
    const tokenRecord = await db.get(`oauthTokens/${tokenHash}`);

    if (tokenRecord) {
      await db.update(`oauthTokens/${tokenHash}`, { revoked: true, revokedAt: Date.now() });
    }

    return true;
  }

  /**
   * Checks if a user has already granted consent to a client for scopes.
   */
  async hasUserConsented(drexoraUserId, clientId, requestedScopes) {
    const consent = await db.get(`oauthConsents/${drexoraUserId}/${clientId}`);
    if (!consent || !consent.grantedScopes) return false;

    const reqList = Array.isArray(requestedScopes) ? requestedScopes : requestedScopes.split(' ');
    return reqList.every(s => consent.grantedScopes.includes(s));
  }

  /**
   * Records user consent for an application.
   */
  async recordUserConsent(drexoraUserId, clientId, grantedScopes) {
    const reqList = Array.isArray(grantedScopes) ? grantedScopes : grantedScopes.split(' ');
    const now = Date.now();

    const consentData = {
      drexoraUserId,
      clientId,
      grantedScopes: reqList,
      grantedAt: now,
      updatedAt: now
    };

    await db.set(`oauthConsents/${drexoraUserId}/${clientId}`, consentData);
    return consentData;
  }
}

module.exports = new OAuthService();
