const db = require('../db/firebase');
const auditService = require('./audit.service');
const emailService = require('./email.service');
const { generateDrexoraUserId } = require('../utils/id.generator');
const { normalizeEmail, isValidName, isValidPhone, isValidCountry, isValidDateOfBirth } = require('../utils/validator.util');
const { verifyPassword } = require('../utils/password.util');

class UserService {
  /**
   * Helper to parse full name into first and last name if possible
   */
  parseName(fullName = '') {
    const parts = fullName.trim().split(/\s+/);
    if (parts.length === 1) {
      return { firstName: parts[0], lastName: '' };
    }
    const firstName = parts[0];
    const lastName = parts.slice(1).join(' ');
    return { firstName, lastName };
  }

  /**
   * Checks whether all required profile fields are completed.
   * Required fields: firstName, lastName, phone, country.
   */
  isProfileComplete(profile) {
    if (!profile) return false;
    const { firstName, lastName, phone, country } = profile;
    return Boolean(
      firstName && firstName.trim() &&
      lastName && lastName.trim() &&
      phone && phone.trim() &&
      country && country.trim()
    );
  }

  /**
   * Calculates comprehensive profile status and completion percentage.
   */
  getProfileStatus(user) {
    if (!user) return null;
    const profile = user.profile || {};

    const requiredFields = [
      { key: 'firstName', label: 'First Name', value: profile.firstName },
      { key: 'lastName', label: 'Last Name', value: profile.lastName },
      { key: 'phone', label: 'Phone Number', value: profile.phone },
      { key: 'country', label: 'Country', value: profile.country }
    ];

    const optionalFields = [
      { key: 'state', label: 'State/Province', value: profile.state },
      { key: 'city', label: 'City', value: profile.city },
      { key: 'address', label: 'Address', value: profile.address },
      { key: 'postalCode', label: 'Postal/ZIP Code', value: profile.postalCode },
      { key: 'profilePhoto', label: 'Profile Photo', value: profile.profilePhoto },
      { key: 'dateOfBirth', label: 'Date of Birth', value: profile.dateOfBirth },
      { key: 'preferredLanguage', label: 'Preferred Language', value: profile.preferredLanguage }
    ];

    const missingRequired = requiredFields.filter(f => !f.value || !String(f.value).trim()).map(f => f.key);
    const filledRequiredCount = requiredFields.length - missingRequired.length;
    const filledOptionalCount = optionalFields.filter(f => f.value && String(f.value).trim()).length;

    // Weighting: 70% for required fields, 30% for optional fields
    const requiredScore = (filledRequiredCount / requiredFields.length) * 70;
    const optionalScore = (filledOptionalCount / optionalFields.length) * 30;
    const completionPercentage = Math.min(100, Math.round(requiredScore + optionalScore));

    const verifiedFields = [];
    if (user.emailVerified) verifiedFields.push('email');
    if (user.phoneVerified) verifiedFields.push('phone');

    return {
      emailVerified: Boolean(user.emailVerified),
      phoneVerified: Boolean(user.phoneVerified),
      profileCompleted: Boolean(user.profileCompleted),
      missingRequiredFields: missingRequired,
      verifiedFields,
      completionPercentage,
      updatedAt: user.metadata ? user.metadata.updatedAt || user.metadata.createdAt : Date.now()
    };
  }
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
    const { firstName, lastName } = this.parseName(fullName);

    const userData = {
      drexoraUserId,
      profile: {
        firstName,
        lastName,
        displayName: fullName.trim(),
        fullName: fullName.trim(),
        email: normalized,
        pendingEmail: null,
        phone: null,
        country: null,
        state: null,
        city: null,
        address: null,
        postalCode: null,
        profilePhoto: null,
        dateOfBirth: null,
        preferredLanguage: null
      },
      security: {
        passwordHash,
        passwordLastChangedAt: now
      },
      accountStatus: 'email_unverified', // 'active' | 'email_unverified' | 'suspended' | 'disabled'
      emailVerified: false,
      phoneVerified: false,
      profileCompleted: false,
      metadata: {
        createdAt: now,
        lastLoginAt: null,
        updatedAt: now
      }
    };

    // Save user record
    await db.set(`users/${drexoraUserId}`, userData);

    // Save email index for O(1) lookup
    await db.set(`emailIndex/${encodeEmailForDb(normalized)}`, { drexoraUserId });

    return userData;
  }

  /**
   * Updates user profile fields with backend validation and sanitization.
   * Required fields: firstName, lastName, phone, country.
   * Resets phoneVerified to false if phone number is changed.
   */
  async updateProfile(drexoraUserId, updates = {}) {
    const user = await this.findByUserId(drexoraUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    const currentProfile = user.profile || {};
    const updatedProfile = { ...currentProfile };
    let phoneChanged = false;

    if (typeof updates.firstName === 'string') {
      const val = updates.firstName.trim();
      if (!val) throw { status: 400, message: 'First name is required' };
      if (!isValidName(val)) throw { status: 400, message: 'First name must be between 2 and 100 characters' };
      updatedProfile.firstName = val;
    }

    if (typeof updates.lastName === 'string') {
      const val = updates.lastName.trim();
      if (!val) throw { status: 400, message: 'Last name is required' };
      if (!isValidName(val)) throw { status: 400, message: 'Last name must be between 2 and 100 characters' };
      updatedProfile.lastName = val;
    }

    if (typeof updates.displayName === 'string') {
      updatedProfile.displayName = updates.displayName.trim();
    }

    if (typeof updates.fullName === 'string' && updates.fullName.trim()) {
      updatedProfile.fullName = updates.fullName.trim();
    } else if (updatedProfile.firstName || updatedProfile.lastName) {
      updatedProfile.fullName = `${updatedProfile.firstName || ''} ${updatedProfile.lastName || ''}`.trim();
    }

    if (!updatedProfile.displayName) {
      updatedProfile.displayName = updatedProfile.fullName;
    }

    if (typeof updates.phone === 'string') {
      const val = updates.phone.trim();
      if (val) {
        if (!isValidPhone(val)) throw { status: 400, message: 'Invalid phone number format' };
        if (currentProfile.phone !== val) {
          updatedProfile.phone = val;
          phoneChanged = true;
        }
      } else {
        if (currentProfile.phone) {
          updatedProfile.phone = null;
          phoneChanged = true;
        }
      }
    }

    if (typeof updates.country === 'string') {
      const val = updates.country.trim();
      if (val) {
        if (!isValidCountry(val)) throw { status: 400, message: 'Invalid country name' };
        updatedProfile.country = val;
      } else {
        updatedProfile.country = null;
      }
    }

    if (typeof updates.state === 'string') updatedProfile.state = updates.state.trim() || null;
    if (typeof updates.city === 'string') updatedProfile.city = updates.city.trim() || null;
    if (typeof updates.address === 'string') updatedProfile.address = updates.address.trim() || null;
    if (typeof updates.postalCode === 'string') updatedProfile.postalCode = updates.postalCode.trim() || null;
    if (typeof updates.profilePhoto === 'string') updatedProfile.profilePhoto = updates.profilePhoto.trim() || null;
    if (typeof updates.preferredLanguage === 'string') updatedProfile.preferredLanguage = updates.preferredLanguage.trim() || null;

    if (typeof updates.dateOfBirth === 'string') {
      const val = updates.dateOfBirth.trim();
      if (val) {
        if (!isValidDateOfBirth(val)) throw { status: 400, message: 'Invalid date of birth. Must be a past date in YYYY-MM-DD format.' };
        updatedProfile.dateOfBirth = val;
      } else {
        updatedProfile.dateOfBirth = null;
      }
    }

    const now = Date.now();
    const isComplete = this.isProfileComplete(updatedProfile);

    const dbUpdates = {
      profile: updatedProfile,
      profileCompleted: isComplete,
      'metadata/updatedAt': now
    };

    if (phoneChanged) {
      dbUpdates.phoneVerified = false;
    }

    await db.update(`users/${drexoraUserId}`, dbUpdates);

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
    const user = await this.findByUserId(drexoraUserId);
    const isComplete = this.isProfileComplete(user ? user.profile : null);

    await db.update(`users/${drexoraUserId}`, {
      emailVerified: true,
      profileCompleted: isComplete,
      accountStatus: 'active',
      'metadata/updatedAt': Date.now()
    });
  }

  /**
   * Marks phone number as verified.
   */
  async markPhoneVerified(drexoraUserId) {
    const user = await this.findByUserId(drexoraUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    const isComplete = this.isProfileComplete(user.profile);

    await db.update(`users/${drexoraUserId}`, {
      phoneVerified: true,
      profileCompleted: isComplete,
      'metadata/updatedAt': Date.now()
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
   * Performs safe account deletion workflow for an authenticated user.
   */
  async deleteAccount(user, password) {
    if (!password) {
      throw { status: 400, error: 'invalid_request', error_description: 'Password confirmation is required to delete account' };
    }

    const isValidPassword = await verifyPassword(password, user.security.passwordHash);
    if (!isValidPassword) {
      throw { status: 400, error: 'invalid_credentials', error_description: 'Password verification failed. Incorrect password.' };
    }

    const drexoraUserId = user.drexoraUserId;
    const userEmail = user.profile.email;

    // 1. Revoke all active user sessions
    const sessionService = require('./session.service');
    await sessionService.revokeAllUserSessions(drexoraUserId);

    // 2. Revoke all OAuth consents and tokens for this user
    await db.remove(`oauthConsents/${drexoraUserId}`);

    const allTokens = await db.get('oauthTokens');
    if (allTokens) {
      for (const [tokenHash, tokenRecord] of Object.entries(allTokens)) {
        if (tokenRecord.drexoraUserId === drexoraUserId && !tokenRecord.revoked) {
          await db.update(`oauthTokens/${tokenHash}`, {
            revoked: true,
            revokedAt: Date.now(),
            revokedReason: 'user_account_deleted'
          });
        }
      }
    }

    // 3. Disable developer applications owned by user
    const clients = await db.get('oauthClients');
    if (clients) {
      for (const [clientId, client] of Object.entries(clients)) {
        if (client.owner && client.owner.ownerId === drexoraUserId) {
          await db.update(`oauthClients/${clientId}`, {
            status: 'disabled',
            verificationStatus: 'rejected',
            updatedAt: Date.now()
          });
        }
      }
    }

    // 4. Remove email index entry
    await db.remove(`emailIndex/${encodeEmailForDb(userEmail)}`);

    // 5. Update user status to 'disabled' / 'deleted'
    await db.update(`users/${drexoraUserId}`, {
      accountStatus: 'disabled',
      emailVerified: false,
      'profile/fullName': 'Deleted User',
      'profile/email': `deleted_${drexoraUserId}@deleted.drexora.com`,
      'security/passwordHash': 'DELETED'
    });

    // 6. Log audit event
    await auditService.logEvent({
      event: 'account.deleted',
      userId: drexoraUserId
    });

    // 7. Send security alert
    emailService.sendSecurityAlert(
      userEmail,
      'Account Deleted',
      'Your Drexora Account has been permanently closed and all active sessions and application permissions have been revoked.'
    ).catch(() => {});

    return { status: 'success', message: 'Your account has been successfully deleted.' };
  }

  /**
   * Strips sensitive security fields from user object before returning to client.
   */
  toPublicProfile(user) {
    if (!user) return null;
    const profile = user.profile || {};
    const status = this.getProfileStatus(user);

    return {
      drexoraUserId: user.drexoraUserId,
      firstName: profile.firstName || '',
      lastName: profile.lastName || '',
      displayName: profile.displayName || profile.fullName || '',
      fullName: profile.fullName || `${profile.firstName || ''} ${profile.lastName || ''}`.trim(),
      email: profile.email,
      pendingEmail: profile.pendingEmail || null,
      phone: profile.phone || null,
      country: profile.country || null,
      state: profile.state || null,
      city: profile.city || null,
      address: profile.address || null,
      postalCode: profile.postalCode || null,
      profilePhoto: profile.profilePhoto || null,
      dateOfBirth: profile.dateOfBirth || null,
      preferredLanguage: profile.preferredLanguage || null,
      emailVerified: Boolean(user.emailVerified),
      phoneVerified: Boolean(user.phoneVerified),
      profileCompleted: Boolean(user.profileCompleted),
      accountStatus: user.accountStatus,
      createdAt: user.metadata ? user.metadata.createdAt : null,
      lastLoginAt: user.metadata ? user.metadata.lastLoginAt : null,
      profileStatus: status
    };
  }
}

function encodeEmailForDb(email) {
  return email.replace(/\./g, '%2E').replace(/@/g, '%40');
}

module.exports = new UserService();
