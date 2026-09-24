const db = require('../db/firebase');
const { generateDrexoraUserId } = require('../utils/id.generator');
const { normalizeEmail } = require('../utils/validator.util');

class UserService {
  /**
   * Finds a user record by Drexora User ID.
   * @param {string} drexoraUserId
   * @returns {Promise<object|null>}
   */
  async findByUserId(drexoraUserId) {
    if (!drexoraUserId) return null;
    return await db.get(`users/${drexoraUserId}`);
  }

  /**
   * Finds a user ID by normalized email address.
   * @param {string} email
   * @returns {Promise<object|null>} Returns user object or null
   */
  async findByEmail(email) {
    const normalized = normalizeEmail(email);
    if (!normalized) return null;

    // Look up in emailIndex
    const indexed = await db.get(`emailIndex/${encodeEmailForDb(normalized)}`);
    if (!indexed || !indexed.drexoraUserId) return null;

    return await this.findByUserId(indexed.drexoraUserId);
  }

  /**
   * Creates a new user record.
   * @param {object} param0 { fullName, email, passwordHash }
   */
  async createUser({ fullName, email, passwordHash }) {
    const normalized = normalizeEmail(email);
    const drexoraUserId = generateDrexoraUserId();
    const now = Date.now();

    const userData = {
      drexoraUserId,
      profile: {
        fullName: fullName.trim(),
        email: normalized,
        pendingEmail: null
      },
      security: {
        passwordHash,
        passwordLastChangedAt: now
      },
      accountStatus: 'email_unverified', // 'active' | 'email_unverified' | 'suspended' | 'disabled'
      emailVerified: false,
      metadata: {
        createdAt: now,
        lastLoginAt: null
      }
    };

    // Save user record
    await db.set(`users/${drexoraUserId}`, userData);

    // Save email index for O(1) lookup
    await db.set(`emailIndex/${encodeEmailForDb(normalized)}`, { drexoraUserId });

    return userData;
  }

  /**
   * Updates user profile fields (e.g. name).
   * Ensures sensitive fields like user ID, account status, etc. cannot be modified directly via profile update.
   */
  async updateProfile(drexoraUserId, updates) {
    const user = await this.findByUserId(drexoraUserId);
    if (!user) throw new Error('User not found');

    const allowedUpdates = {};
    if (typeof updates.fullName === 'string' && updates.fullName.trim()) {
      allowedUpdates['profile/fullName'] = updates.fullName.trim();
    }

    if (Object.keys(allowedUpdates).length > 0) {
      await db.update(`users/${drexoraUserId}`, allowedUpdates);
    }

    return await this.findByUserId(drexoraUserId);
  }

  /**
   * Updates user account status.
   */
  async setAccountStatus(drexoraUserId, status) {
    await db.update(`users/${drexoraUserId}`, { accountStatus: status });
  }

  /**
   * Marks account email as verified.
   */
  async markEmailVerified(drexoraUserId) {
    await db.update(`users/${drexoraUserId}`, {
      emailVerified: true,
      accountStatus: 'active'
    });
  }

  /**
   * Updates user password hash.
   */
  async updatePassword(drexoraUserId, newPasswordHash) {
    const now = Date.now();
    await db.update(`users/${drexoraUserId}/security`, {
      passwordHash: newPasswordHash,
      passwordLastChangedAt: now
    });
  }

  /**
   * Changes primary email address after verification.
   */
  async updatePrimaryEmail(drexoraUserId, newEmail) {
    const user = await this.findByUserId(drexoraUserId);
    if (!user) throw new Error('User not found');

    const oldEmail = user.profile.email;
    const normalizedNew = normalizeEmail(newEmail);

    // Remove old email index and set new email index
    await db.remove(`emailIndex/${encodeEmailForDb(oldEmail)}`);
    await db.set(`emailIndex/${encodeEmailForDb(normalizedNew)}`, { drexoraUserId });

    await db.update(`users/${drexoraUserId}/profile`, {
      email: normalizedNew,
      pendingEmail: null
    });
  }

  /**
   * Sets pending new email for user email change request.
   */
  async setPendingEmail(drexoraUserId, pendingEmail) {
    await db.update(`users/${drexoraUserId}/profile`, {
      pendingEmail: normalizeEmail(pendingEmail)
    });
  }

  /**
   * Strips sensitive security fields from user object before returning to client.
   */
  toPublicProfile(user) {
    if (!user) return null;
    return {
      drexoraUserId: user.drexoraUserId,
      fullName: user.profile.fullName,
      email: user.profile.email,
      pendingEmail: user.profile.pendingEmail || null,
      emailVerified: user.emailVerified,
      accountStatus: user.accountStatus,
      createdAt: user.metadata.createdAt,
      lastLoginAt: user.metadata.lastLoginAt
    };
  }
}

function encodeEmailForDb(email) {
  return email.replace(/\./g, '%2E').replace(/@/g, '%40');
}

module.exports = new UserService();
