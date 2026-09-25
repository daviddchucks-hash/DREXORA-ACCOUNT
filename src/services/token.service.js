const crypto = require('crypto');
const db = require('../db/firebase');
const { generateSecureToken, hashToken } = require('../utils/id.generator');

class TokenService {
  /**
   * Generates a cryptographically secure 8-digit numeric verification code.
   * Example: "84920153"
   */
  generateNumericCode(digits = 8) {
    const min = Math.pow(10, digits - 1);
    const max = Math.pow(10, digits) - 1;
    const randomInt = crypto.randomInt(min, max + 1);
    return randomInt.toString();
  }

  /**
   * Creates a hashed single-use token or code in the database.
   * @param {string} category Node path
   * @param {object} payload Additional metadata
   * @param {number} expiresInMs Expiration in milliseconds
   * @param {boolean} isNumericCode Whether to generate an 8-digit numeric code
   * @returns {Promise<{ rawToken: string, hashedToken: string }>}
   */
  async createToken(category, payload, expiresInMs, isNumericCode = false) {
    const rawToken = isNumericCode ? this.generateNumericCode(8) : generateSecureToken(32);
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
   * Verifies and consumes a single-use token or 8-digit code.
   * @param {string} category
   * @param {string} rawToken
   * @returns {Promise<{ valid: boolean, reason?: string, data?: object }>}
   */
  async verifyAndConsumeToken(category, rawToken) {
    if (!rawToken || typeof rawToken !== 'string') {
      return { valid: false, reason: 'missing_or_invalid_format' };
    }

    const trimmed = rawToken.trim();
    const hashedToken = hashToken(trimmed);
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

    // Mark as used immediately
    await db.update(`${category}/${hashedToken}`, {
      used: true,
      usedAt: Date.now()
    });

    return { valid: true, data: tokenRecord };
  }
}

module.exports = new TokenService();
