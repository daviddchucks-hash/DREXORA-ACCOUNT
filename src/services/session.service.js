const useragent = require('useragent');
const db = require('../db/firebase');
const config = require('../config');
const { generateSecureToken, hashToken } = require('../utils/id.generator');

class SessionService {
  /**
   * Creates a new session for a user.
   * @param {string} drexoraUserId
   * @param {object} req Express request object (for IP and User-Agent)
   */
  async createSession(drexoraUserId, req) {
    const rawSessionId = generateSecureToken(32);
    const hashedSessionId = hashToken(rawSessionId);
    const now = Date.now();
    const expiresAt = now + (config.session.maxAgeDays * 24 * 60 * 60 * 1000);

    const uaString = req.headers['user-agent'] || '';
    const agent = useragent.parse(uaString);

    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    const sessionData = {
      sessionId: hashedSessionId,
      drexoraUserId,
      createdAt: now,
      lastActivity: now,
      expiresAt,
      revoked: false,
      ipAddress: typeof ipAddress === 'string' ? ipAddress.split(',')[0].trim() : '127.0.0.1',
      deviceInfo: {
        browser: agent.toAgent(),
        os: agent.os.toString(),
        device: agent.device.toString(),
        userAgent: uaString.substring(0, 200)
      }
    };

    // Store in sessions tree
    await db.set(`sessions/${hashedSessionId}`, sessionData);

    // Also link under user's sessions index
    await db.set(`userSessions/${drexoraUserId}/${hashedSessionId}`, {
      createdAt: now,
      lastActivity: now
    });

    return { rawSessionId, hashedSessionId, sessionData };
  }

  /**
   * Retrieves and validates a active session by raw session ID.
   * Updates lastActivity timestamp.
   * @param {string} rawSessionId
   */
  async getValidSession(rawSessionId) {
    if (!rawSessionId || typeof rawSessionId !== 'string') return null;

    const hashedSessionId = hashToken(rawSessionId);
    const session = await db.get(`sessions/${hashedSessionId}`);

    if (!session || session.revoked) return null;

    if (Date.now() > session.expiresAt) {
      // Mark revoked/expired
      await db.update(`sessions/${hashedSessionId}`, { revoked: true, revokedReason: 'expired' });
      return null;
    }

    // Throttle lastActivity update to once every 5 minutes to reduce DB writes
    const now = Date.now();
    if (now - session.lastActivity > 5 * 60 * 1000) {
      await db.update(`sessions/${hashedSessionId}`, { lastActivity: now });
      await db.update(`userSessions/${session.drexoraUserId}/${hashedSessionId}`, { lastActivity: now });
      session.lastActivity = now;
    }

    return session;
  }

  /**
   * Gets all sessions for a specific user.
   * Highlights the current active session.
   * @param {string} drexoraUserId
   * @param {string} currentRawSessionId
   */
  async getUserSessions(drexoraUserId, currentRawSessionId) {
    const currentHashed = currentRawSessionId ? hashToken(currentRawSessionId) : null;
    const userSessionIndex = (await db.get(`userSessions/${drexoraUserId}`)) || {};

    const sessionIds = Object.keys(userSessionIndex);
    const activeSessions = [];

    for (const sid of sessionIds) {
      const session = await db.get(`sessions/${sid}`);
      if (session && !session.revoked && session.expiresAt > Date.now()) {
        activeSessions.push({
          sessionId: sid,
          isCurrent: sid === currentHashed,
          createdAt: session.createdAt,
          lastActivity: session.lastActivity,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress
        });
      }
    }

    // Sort by last activity descending
    return activeSessions.sort((a, b) => b.lastActivity - a.lastActivity);
  }

  /**
   * Revokes a specific session for a user.
   * @param {string} drexoraUserId
   * @param {string} targetHashedSessionId
   */
  async revokeSession(drexoraUserId, targetHashedSessionId) {
    const session = await db.get(`sessions/${targetHashedSessionId}`);
    if (!session || session.drexoraUserId !== drexoraUserId) {
      return false;
    }

    await db.update(`sessions/${targetHashedSessionId}`, {
      revoked: true,
      revokedAt: Date.now()
    });
    await db.remove(`userSessions/${drexoraUserId}/${targetHashedSessionId}`);
    return true;
  }

  /**
   * Revokes all sessions for a user EXCEPT the specified current session.
   * @param {string} drexoraUserId
   * @param {string} currentRawSessionId
   */
  async revokeAllOtherSessions(drexoraUserId, currentRawSessionId) {
    const currentHashed = currentRawSessionId ? hashToken(currentRawSessionId) : null;
    const userSessionIndex = (await db.get(`userSessions/${drexoraUserId}`)) || {};

    const sessionIds = Object.keys(userSessionIndex);
    let revokedCount = 0;

    for (const sid of sessionIds) {
      if (sid !== currentHashed) {
        await db.update(`sessions/${sid}`, {
          revoked: true,
          revokedAt: Date.now()
        });
        await db.remove(`userSessions/${drexoraUserId}/${sid}`);
        revokedCount++;
      }
    }

    return revokedCount;
  }

  /**
   * Revokes all sessions for a user (e.g., after password reset/change).
   * @param {string} drexoraUserId
   */
  async revokeAllUserSessions(drexoraUserId) {
    const userSessionIndex = (await db.get(`userSessions/${drexoraUserId}`)) || {};
    const sessionIds = Object.keys(userSessionIndex);

    for (const sid of sessionIds) {
      await db.update(`sessions/${sid}`, {
        revoked: true,
        revokedAt: Date.now()
      });
    }
    await db.remove(`userSessions/${drexoraUserId}`);
  }
}

module.exports = new SessionService();
