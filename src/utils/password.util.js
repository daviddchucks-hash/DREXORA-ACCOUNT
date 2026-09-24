let argon2 = null;
try {
  argon2 = require('argon2');
} catch (e) {
  // Argon2 prebuilt binary might not be available in some environments
  argon2 = null;
}
const bcrypt = require('bcryptjs');

const BCRYPT_SALT_ROUNDS = 12;

/**
 * Securely hashes a password using Argon2id with bcrypt fallback.
 * @param {string} password
 * @returns {Promise<string>}
 */
async function hashPassword(password) {
  if (argon2) {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16, // 64MB
        timeCost: 3,
        parallelism: 1
      });
    } catch (err) {
      // Fallback to bcrypt if argon2 fails at runtime
      return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    }
  }
  return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

/**
 * Verifies a plain password against a stored hash (Argon2id or bcrypt).
 * @param {string} password
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, hash) {
  if (!password || !hash) return false;

  // Check if hash is argon2 (starts with $argon2)
  if (hash.startsWith('$argon2')) {
    if (argon2) {
      try {
        return await argon2.verify(hash, password);
      } catch (err) {
        return false;
      }
    } else {
      // If argon2 is not loaded but hash is argon2, cannot verify without argon2
      return false;
    }
  }

  // Fallback / standard bcrypt check
  try {
    return await bcrypt.compare(password, hash);
  } catch (err) {
    return false;
  }
}

module.exports = {
  hashPassword,
  verifyPassword
};
