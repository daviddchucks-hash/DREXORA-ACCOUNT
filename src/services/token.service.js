const db = require('../db/firebase');
const { generateSecureToken, hashToken } = require('../utils/id.generator');

class TokenService {
  /**
   * Creates a hashed single-use token in the database.
   * @param {string} category Node path (e.g. 'verificationTokens', 'passwordResetTokens', 'emailChangeTokens')
   * @param {object} payload Additional metadata (userId, email, etc.)
   * @param {number} expiresInMs Expiration in milliseconds
   * @returns {Promise<{ rawToken: string, hashedToken: string }>}
   */
  async createToken(category, payload, expiresInMs) {
    const rawToken = generateSecureToken(32);
    const hashedToken = hashToken(rawToken);
    const expiresAt = Date.now() + expiresInMs;

    const tokenData = {
      ...payload,
      tokenHash: hashedToken,
      expiresAt,
      used: false,
      createdAt: Date.now()
    };

    await db.set(`${category}/${hashedToken}`, tokenData);
    return { rawToken, hashedToken };
  }

  /**
   * Verifies and consumes a single-use token.
   * @param {string} category
   * @param {string} rawToken
   * @returns {Promise<{ valid: boolean, reason?: string, data?: object }>}
   */
  async verifyAndConsumeToken(category, rawToken) {
    if (!rawToken || typeof rawToken !== 'string') {
      return { valid: false, reason: 'missing_or_invalid_format' };
    }

    const hashedToken = hashToken(rawToken);
    const tokenRecord = await db.get(`${category}/${hashedToken}`);

    if (!tokenRecord) {
      return { valid: false, reason: 'not_found' };
    }

    if (tokenRecord.used) {
      return { valid: false, reason: 'already_used' };
    }

    if (Date.now() > tokenRecord.expiresAt) {
      return { valid: false, reason: 'expired' };
    }

    // Mark as used immediately (single-use)
    await db.update(`${category}/${hashedToken}`, {
      used: true,
      usedAt: Date.now()
    });

    return { valid: true, data: tokenRecord };
  }
}

module.exports = new TokenService();
