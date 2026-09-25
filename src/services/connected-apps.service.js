const db = require('../db/firebase');
const oauthService = require('./oauth.service');
const auditService = require('./audit.service');
const emailService = require('./email.service');

class ConnectedAppsService {
  /**
   * Lists all connected applications for a given user.
   */
  async getUserConnectedApps(drexoraUserId) {
    if (!drexoraUserId) return [];

    const consents = await db.get(`oauthConsents/${drexoraUserId}`);
    if (!consents) return [];

    const connectedApps = [];

    for (const [clientId, consent] of Object.entries(consents)) {
      if (!consent || consent.revoked) continue;

      const app = await oauthService.getClient(clientId);

      connectedApps.push({
        clientId,
        applicationName: app ? app.name : 'Unknown Application',
        description: app ? app.description : '',
        appType: app ? app.appType : 'external_application',
        grantedScopes: consent.grantedScopes || [],
        grantedAt: consent.grantedAt,
        updatedAt: consent.updatedAt
      });
    }

    return connectedApps.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /**
   * Revokes access to a specific connected application for a user.
   * Invalidates consent AND revokes all active OAuth tokens issued to this client for this user.
   */
  async revokeConnectedApp(drexoraUserId, clientId, userEmail = null) {
    if (!drexoraUserId || !clientId) {
      throw { status: 400, error: 'invalid_request', error_description: 'User ID and Client ID are required' };
    }

    const consent = await db.get(`oauthConsents/${drexoraUserId}/${clientId}`);
    if (!consent) {
      throw { status: 404, error: 'not_found', error_description: 'Connected application access record not found' };
    }

    // 1. Remove/revoke consent record
    await db.remove(`oauthConsents/${drexoraUserId}/${clientId}`);

    // 2. Revoke all active OAuth tokens for this (user, client) pair
    const allTokens = await db.get('oauthTokens');
    if (allTokens) {
      for (const [tokenHash, tokenRecord] of Object.entries(allTokens)) {
        if (
          tokenRecord.drexoraUserId === drexoraUserId &&
          tokenRecord.clientId === clientId &&
          !tokenRecord.revoked
        ) {
          await db.update(`oauthTokens/${tokenHash}`, {
            revoked: true,
            revokedAt: Date.now(),
            revokedReason: 'user_revoked_app_access'
          });
        }
      }
    }

    // 3. Log audit event
    const app = await oauthService.getClient(clientId);
    const appName = app ? app.name : clientId;

    await auditService.logEvent({
      event: 'application.access.revoked',
      userId: drexoraUserId,
      clientId,
      metadata: { appName }
    });

    // 4. Send security notification email if user email provided
    if (userEmail) {
      emailService.sendSecurityAlert(
        userEmail,
        'Application Access Revoked',
        `Access for the application "${appName}" was revoked from your Drexora Account. The application will no longer be able to access your account details without your explicit consent.`
      ).catch(() => {});
    }

    return { status: 'success', message: `Access for '${appName}' has been successfully revoked` };
  }
}

module.exports = new ConnectedAppsService();
