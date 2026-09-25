const db = require('../db/firebase');
const emailService = require('./email.service');
const { generateSecureToken } = require('../utils/id.generator');

const SENSITIVE_KEYS = [
  'password',
  'passwordhash',
  'clientsecret',
  'clientsecrethash',
  'token',
  'accesstoken',
  'refreshtoken',
  'authorizationcode',
  'codeverifier',
  'codechallenge',
  'jwtsecret',
  'sessionsecret'
];

class AuditService {
  /**
   * Sanitizes metadata objects by stripping any credentials, secrets, or raw tokens.
   */
  sanitizeMetadata(metadata) {
    if (!metadata || typeof metadata !== 'object') return {};
    const clean = {};
    for (const [key, val] of Object.entries(metadata)) {
      const lowerKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (SENSITIVE_KEYS.some(s => lowerKey.includes(s))) {
        clean[key] = '[REDACTED]';
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        clean[key] = this.sanitizeMetadata(val);
      } else {
        clean[key] = val;
      }
    }
    return clean;
  }

  /**
   * Records a security / platform audit log event.
   */
  async logEvent({
    event,
    userId = null,
    clientId = null,
    ipAddress = null,
    userAgent = null,
    metadata = {}
  }) {
    if (!event) return null;

    const auditId = `audit_${generateSecureToken(16)}`;
    const now = Date.now();

    const sanitizedMeta = this.sanitizeMetadata(metadata);

    const logRecord = {
      auditId,
      event,
      userId: userId || null,
      clientId: clientId || null,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      metadata: sanitizedMeta,
      timestamp: now
    };

    await db.set(`auditLogs/${auditId}`, logRecord);

    // Also index under user's audit logs if userId is present
    if (userId) {
      await db.set(`userAuditLogs/${userId}/${auditId}`, {
        auditId,
        event,
        clientId,
        timestamp: now
      });
    }

    return logRecord;
  }

  /**
   * Retrieves audit logs for a specific user.
   */
  async getUserAuditLogs(userId, limit = 50) {
    if (!userId) return [];
    const logs = await db.get(`userAuditLogs/${userId}`);
    if (!logs) return [];
    const sorted = Object.values(logs)
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);
    return sorted;
  }
}

module.exports = new AuditService();
