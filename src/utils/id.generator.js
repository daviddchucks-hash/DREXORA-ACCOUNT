const crypto = require('crypto');

/**
 * Generates a permanent, cryptographically secure Drexora User ID.
 * Example: dx_8f72abc123
 */
function generateDrexoraUserId() {
  const randomBytes = crypto.randomBytes(8).toString('hex'); // 16 random hex chars
  return `dx_${randomBytes}`;
}

/**
 * Generates a secure random token string for session identifiers, verification tokens, etc.
 * @param {number} bytes Length in bytes
 */
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Returns SHA-256 hash of token to avoid storing raw tokens in database.
 * @param {string} token
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  generateDrexoraUserId,
  generateSecureToken,
  hashToken
};
