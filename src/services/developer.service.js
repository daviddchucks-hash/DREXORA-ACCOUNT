const db = require('../db/firebase');
const oauthService = require('./oauth.service');
const auditService = require('./audit.service');
const { generateSecureToken, hashToken } = require('../utils/id.generator');

// Global Scope Registry
const GLOBAL_SCOPE_REGISTRY = [
  { key: 'openid', name: 'OpenID Connect', description: 'Authenticate identity and obtain unique Drexora User ID (sub)', isDefault: true },
  { key: 'profile', name: 'Profile Details', description: 'Access full name and basic public profile details', isDefault: false },
  { key: 'email', name: 'Email Address', description: 'Access primary email address and email verification status', isDefault: false },
  { key: 'profile.read', name: 'Read Profile', description: 'Read-only access to user profile name', isDefault: false },
  { key: 'email.read', name: 'Read Email', description: 'Read-only access to email address', isDefault: false },
  { key: 'account.read', name: 'Read Account Info', description: 'Access basic account metadata', isDefault: false }
];

class DeveloperService {
  /**
   * Returns the central list of valid platform scopes.
   */
  getGlobalScopes() {
    return GLOBAL_SCOPE_REGISTRY;
  }

  /**
   * Validates target scopes against global scope registry.
   */
  validateScopes(requestedScopes = []) {
    const validKeys = GLOBAL_SCOPE_REGISTRY.map(s => s.key);
    const scopeList = Array.isArray(requestedScopes)
      ? requestedScopes
      : requestedScopes.split(' ').map(s => s.trim()).filter(Boolean);

    for (const s of scopeList) {
      if (!validKeys.includes(s)) {
        throw { status: 400, error: 'invalid_scope', error_description: `Scope '${s}' is not a valid platform scope` };
      }
    }
    return scopeList.length > 0 ? scopeList : ['openid'];
  }

  /**
   * Validates redirect URIs for safety.
   * Production requires HTTPS (or localhost for dev).
   */
  validateRedirectUris(redirectUris = []) {
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw { status: 400, error: 'invalid_request', error_description: 'At least one valid redirect URI is required' };
    }

    const cleanUris = [];
    for (const uri of redirectUris) {
      const trimmed = uri.trim();
      if (!trimmed) continue;

      let parsed;
      try {
        parsed = new URL(trimmed);
      } catch (e) {
        throw { status: 400, error: 'invalid_request', error_description: `Invalid URL format: '${trimmed}'` };
      }

      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw { status: 400, error: 'invalid_request', error_description: `Redirect URI scheme must be HTTP or HTTPS: '${trimmed}'` };
      }

      // Enforce HTTPS in production for non-localhost
      const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
      if (process.env.NODE_ENV === 'production' && !isLocalhost && parsed.protocol !== 'https:') {
        throw { status: 400, error: 'invalid_request', error_description: `Redirect URIs must use HTTPS in production: '${trimmed}'` };
      }

      if (parsed.hash) {
        throw { status: 400, error: 'invalid_request', error_description: `Redirect URIs must not contain fragment identifiers: '${trimmed}'` };
      }

      cleanUris.push(trimmed);
    }

    if (cleanUris.length === 0) {
      throw { status: 400, error: 'invalid_request', error_description: 'At least one valid redirect URI is required' };
    }

    return cleanUris;
  }

  /**
   * Lists all applications owned by a given developer / user.
   */
  async getDeveloperApplications(ownerId) {
    if (!ownerId) return [];
    const clients = await db.get('oauthClients');
    if (!clients) return [];

    const ownerApps = Object.values(clients)
      .filter(app => app.owner && app.owner.ownerId === ownerId)
      .map(app => {
        // Strip sensitive clientSecretHash before sending to client
        const { clientSecretHash, ...safeApp } = app;
        return safeApp;
      })
      .sort((a, b) => b.createdAt - a.createdAt);

    return ownerApps;
  }

  /**
   * Retrieves a specific application and enforces ownership.
   */
  async getDeveloperApplicationById(clientId, ownerId) {
    if (!clientId) {
      throw { status: 400, error: 'invalid_request', error_description: 'Client ID is required' };
    }

    const client = await oauthService.getClient(clientId);
    if (!client) {
      throw { status: 404, error: 'not_found', error_description: 'Application not found' };
    }

    // Ownership check (HPE Prevention)
    if (!client.owner || client.owner.ownerId !== ownerId) {
      throw { status: 403, error: 'forbidden', error_description: 'You are not authorized to access or manage this application' };
    }

    const { clientSecretHash, ...safeApp } = client;
    return safeApp;
  }

  /**
   * Registers a new application owned by the authenticated developer.
   */
  async createApplication(ownerUser, payload) {
    const {
      name,
      description = '',
      clientType = 'public', // 'public' | 'confidential'
      appType = 'external_application', // 'drexora_product' | 'external_application'
      redirectUris = [],
      allowedOrigins = [],
      allowedScopes = ['openid', 'profile', 'email']
    } = payload;

    if (!name || typeof name !== 'string' || !name.trim()) {
      throw { status: 400, error: 'invalid_request', error_description: 'Application name is required' };
    }

    const validatedRedirectUris = this.validateRedirectUris(redirectUris);
    const validatedScopes = this.validateScopes(allowedScopes);

    const ownerInfo = {
      ownerId: ownerUser.drexoraUserId,
      ownerType: 'developer',
      email: ownerUser.profile.email,
      name: ownerUser.profile.fullName
    };

    const registered = await oauthService.registerClient({
      clientType,
      appType,
      name: name.trim(),
      description: description ? description.trim() : '',
      owner: ownerInfo,
      redirectUris: validatedRedirectUris,
      allowedOrigins: Array.isArray(allowedOrigins) ? allowedOrigins.map(o => o.trim()) : [],
      allowedScopes: validatedScopes,
      status: 'active'
    });

    await auditService.logEvent({
      event: 'application.created',
      userId: ownerUser.drexoraUserId,
      clientId: registered.clientId,
      metadata: { appName: registered.name, clientType, appType }
    });

    // Strip clientSecretHash, return clientSecret only once if confidential
    const { clientSecretHash, ...safeRegistered } = registered;
    return safeRegistered;
  }

  /**
   * Updates an existing application owned by the developer.
   */
  async updateApplication(clientId, ownerId, payload) {
    const app = await this.getDeveloperApplicationById(clientId, ownerId);

    const updates = { updatedAt: Date.now() };

    if (payload.name && typeof payload.name === 'string') {
      updates.name = payload.name.trim();
    }

    if (payload.description !== undefined && typeof payload.description === 'string') {
      updates.description = payload.description.trim();
    }

    if (payload.redirectUris) {
      updates.redirectUris = this.validateRedirectUris(payload.redirectUris);
    }

    if (payload.allowedOrigins && Array.isArray(payload.allowedOrigins)) {
      updates.allowedOrigins = payload.allowedOrigins.map(o => o.trim());
    }

    if (payload.allowedScopes) {
      updates.allowedScopes = this.validateScopes(payload.allowedScopes);
    }

    if (payload.status && ['active', 'disabled'].includes(payload.status)) {
      updates.status = payload.status;
    }

    await db.update(`oauthClients/${clientId}`, updates);

    await auditService.logEvent({
      event: 'application.updated',
      userId: ownerId,
      clientId,
      metadata: { updatedFields: Object.keys(updates) }
    });

    return await this.getDeveloperApplicationById(clientId, ownerId);
  }

  /**
   * Secret Rotation for Confidential Clients.
   * Generates new client secret, invalidates old secret hash immediately, returns new secret ONCE.
   */
  async rotateClientSecret(clientId, ownerId) {
    const app = await oauthService.getClient(clientId);
    if (!app) {
      throw { status: 404, error: 'not_found', error_description: 'Application not found' };
    }

    if (!app.owner || app.owner.ownerId !== ownerId) {
      throw { status: 403, error: 'forbidden', error_description: 'You are not authorized to manage this application' };
    }

    if (app.clientType !== 'confidential') {
      throw { status: 400, error: 'invalid_request', error_description: 'Secret rotation is only applicable to confidential client applications' };
    }

    const newSecret = `dx_secret_${generateSecureToken(24)}`;
    const newHash = hashToken(newSecret);

    await db.update(`oauthClients/${clientId}`, {
      clientSecretHash: newHash,
      updatedAt: Date.now()
    });

    await auditService.logEvent({
      event: 'application.secret_rotated',
      userId: ownerId,
      clientId
    });

    return {
      clientId,
      clientSecret: newSecret,
      message: 'New client secret generated. Copy it now, as it will not be shown again.'
    };
  }

  /**
   * Deletes / disables an application owned by developer.
   */
  async deleteApplication(clientId, ownerId) {
    const app = await this.getDeveloperApplicationById(clientId, ownerId);

    // Set status to revoked/disabled
    await db.update(`oauthClients/${clientId}`, {
      status: 'disabled',
      verificationStatus: 'rejected',
      updatedAt: Date.now()
    });

    await auditService.logEvent({
      event: 'application.disabled',
      userId: ownerId,
      clientId
    });

    return { status: 'success', message: 'Application has been disabled' };
  }
}

module.exports = new DeveloperService();
