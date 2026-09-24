const userService = require('./user.service');
const sessionService = require('./session.service');
const tokenService = require('./token.service');
const emailService = require('./email.service');
const { hashPassword, verifyPassword } = require('../utils/password.util');
const { normalizeEmail, isValidEmail, validatePassword, isValidName } = require('../utils/validator.util');

const VERIFICATION_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours
const PASSWORD_RESET_TOKEN_TTL = 60 * 60 * 1000; // 1 hour
const EMAIL_CHANGE_TOKEN_TTL = 2 * 60 * 60 * 1000; // 2 hours

class AuthService {
  /**
   * Complete Registration Flow
   */
  async register({ fullName, email, password, confirmPassword }) {
    if (!fullName || !email || !password || !confirmPassword) {
      throw { status: 400, message: 'All fields are required' };
    }

    if (password !== confirmPassword) {
      throw { status: 400, message: 'Passwords do not match' };
    }

    if (!isValidName(fullName)) {
      throw { status: 400, message: 'Name must be between 2 and 100 characters' };
    }

    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail)) {
      throw { status: 400, message: 'Invalid email address format' };
    }

    const passValidation = validatePassword(password);
    if (!passValidation.valid) {
      throw { status: 400, message: passValidation.message };
    }

    // Check if email already registered
    const existingUser = await userService.findByEmail(normalizedEmail);
    if (existingUser) {
      throw { status: 409, message: 'An account with this email address already exists' };
    }

    // Hash password securely
    const passwordHash = await hashPassword(password);

    // Create user record
    const user = await userService.createUser({
      fullName,
      email: normalizedEmail,
      passwordHash
    });

    // Generate single-use email verification token
    const { rawToken } = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: user.drexoraUserId, email: normalizedEmail },
      VERIFICATION_TOKEN_TTL
    );

    // Send verification email
    await emailService.sendVerificationEmail(normalizedEmail, rawToken, user.profile.fullName);

    return {
      drexoraUserId: user.drexoraUserId,
      email: user.profile.email,
      accountStatus: user.accountStatus,
      message: 'Registration successful. Please verify your email before logging in.'
    };
  }

  /**
   * Email Verification Flow
   */
  async verifyEmail(rawToken) {
    if (!rawToken) {
      throw { status: 400, message: 'Verification token is required' };
    }

    const result = await tokenService.verifyAndConsumeToken('verificationTokens', rawToken);

    if (!result.valid) {
      if (result.reason === 'already_used') {
        throw { status: 400, message: 'This verification link has already been used.' };
      }
      if (result.reason === 'expired') {
        throw { status: 400, message: 'Verification link has expired. Please request a new one.' };
      }
      throw { status: 400, message: 'Invalid or malformed verification link.' };
    }

    const { drexoraUserId } = result.data;
    const user = await userService.findByUserId(drexoraUserId);

    if (!user) {
      throw { status: 404, message: 'User account not found.' };
    }

    if (user.emailVerified) {
      return { message: 'Your email address is already verified. You may log in.' };
    }

    await userService.markEmailVerified(drexoraUserId);

    return {
      drexoraUserId: user.drexoraUserId,
      message: 'Email address verified successfully. You can now log in.'
    };
  }

  /**
   * Resend Verification Email Flow
   */
  async resendVerificationEmail(email) {
    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail)) {
      // Safe generic message to avoid enumeration
      return { message: 'If an unverified account exists with that email, a verification link has been sent.' };
    }

    const user = await userService.findByEmail(normalizedEmail);
    if (!user || user.emailVerified) {
      // Safe response against account enumeration
      return { message: 'If an unverified account exists with that email, a verification link has been sent.' };
    }

    // Check account status
    if (user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
      return { message: 'If an unverified account exists with that email, a verification link has been sent.' };
    }

    const { rawToken } = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: user.drexoraUserId, email: normalizedEmail },
      VERIFICATION_TOKEN_TTL
    );

    await emailService.sendVerificationEmail(normalizedEmail, rawToken, user.profile.fullName);

    return { message: 'If an unverified account exists with that email, a verification link has been sent.' };
  }

  /**
   * Login Flow
   */
  async login({ email, password }, req) {
    if (!email || !password) {
      throw { status: 400, message: 'Email and password are required' };
    }

    const normalizedEmail = normalizeEmail(email);
    const user = await userService.findByEmail(normalizedEmail);

    // Constant-time style generic failure message
    if (!user) {
      throw { status: 401, message: 'Invalid email or password' };
    }

    const isMatch = await verifyPassword(password, user.security.passwordHash);
    if (!isMatch) {
      throw { status: 401, message: 'Invalid email or password' };
    }

    // Check account status
    if (user.accountStatus === 'suspended') {
      throw { status: 403, message: 'Your account has been suspended. Please contact support.' };
    }

    if (user.accountStatus === 'disabled') {
      throw { status: 403, message: 'Your account is disabled.' };
    }

    if (!user.emailVerified || user.accountStatus === 'email_unverified') {
      throw {
        status: 403,
        code: 'EMAIL_UNVERIFIED',
        message: 'Your email address is not verified. Please verify your email before logging in.'
      };
    }

    // Create multi-device server session
    const { rawSessionId, sessionData } = await sessionService.createSession(user.drexoraUserId, req);

    return {
      rawSessionId,
      user: userService.toPublicProfile(user),
      session: sessionData
    };
  }

  /**
   * Request Password Reset Flow
   */
  async requestPasswordReset(email) {
    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail)) {
      return { message: 'If an account exists with that email address, a password reset link has been sent.' };
    }

    const user = await userService.findByEmail(normalizedEmail);
    if (!user || user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
      return { message: 'If an account exists with that email address, a password reset link has been sent.' };
    }

    const { rawToken } = await tokenService.createToken(
      'passwordResetTokens',
      { drexoraUserId: user.drexoraUserId, email: normalizedEmail },
      PASSWORD_RESET_TOKEN_TTL
    );

    await emailService.sendPasswordResetEmail(normalizedEmail, rawToken, user.profile.fullName);

    return { message: 'If an account exists with that email address, a password reset link has been sent.' };
  }

  /**
   * Reset Password Flow
   */
  async resetPassword({ token, newPassword, confirmNewPassword }) {
    if (!token || !newPassword || !confirmNewPassword) {
      throw { status: 400, message: 'All fields are required' };
    }

    if (newPassword !== confirmNewPassword) {
      throw { status: 400, message: 'Passwords do not match' };
    }

    const passValidation = validatePassword(newPassword);
    if (!passValidation.valid) {
      throw { status: 400, message: passValidation.message };
    }

    const result = await tokenService.verifyAndConsumeToken('passwordResetTokens', token);
    if (!result.valid) {
      if (result.reason === 'already_used') {
        throw { status: 400, message: 'This password reset link has already been used.' };
      }
      if (result.reason === 'expired') {
        throw { status: 400, message: 'Password reset link has expired. Please request a new one.' };
      }
      throw { status: 400, message: 'Invalid or malformed password reset link.' };
    }

    const { drexoraUserId, email } = result.data;
    const newHash = await hashPassword(newPassword);

    await userService.updatePassword(drexoraUserId, newHash);

    // Security practice: revoke existing sessions after password reset
    await sessionService.revokeAllUserSessions(drexoraUserId);

    await emailService.sendSecurityAlert(
      email,
      'Password Reset Successful',
      'Your Drexora Account password was recently reset. All active sessions have been logged out for security.'
    );

    return { message: 'Password reset successfully. You may now log in with your new password.' };
  }

  /**
   * Change Password Flow (Authenticated)
   */
  async changePassword(drexoraUserId, { currentPassword, newPassword, confirmNewPassword }, currentRawSessionId) {
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      throw { status: 400, message: 'All fields are required' };
    }

    if (newPassword !== confirmNewPassword) {
      throw { status: 400, message: 'New passwords do not match' };
    }

    const passValidation = validatePassword(newPassword);
    if (!passValidation.valid) {
      throw { status: 400, message: passValidation.message };
    }

    const user = await userService.findByUserId(drexoraUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    const isCurrentCorrect = await verifyPassword(currentPassword, user.security.passwordHash);
    if (!isCurrentCorrect) {
      throw { status: 400, message: 'Current password is incorrect' };
    }

    const newHash = await hashPassword(newPassword);
    await userService.updatePassword(drexoraUserId, newHash);

    // Revoke all other sessions for security, keep current session
    await sessionService.revokeAllOtherSessions(drexoraUserId, currentRawSessionId);

    await emailService.sendSecurityAlert(
      user.profile.email,
      'Password Changed',
      'Your Drexora Account password was changed. All other device sessions were logged out.'
    );

    return { message: 'Password updated successfully. Other active sessions have been logged out.' };
  }

  /**
   * Request Email Change Flow (Authenticated)
   */
  async requestEmailChange(drexoraUserId, { newEmail, currentPassword }) {
    if (!newEmail || !currentPassword) {
      throw { status: 400, message: 'New email and current password are required' };
    }

    const normalizedNewEmail = normalizeEmail(newEmail);
    if (!isValidEmail(normalizedNewEmail)) {
      throw { status: 400, message: 'Invalid new email address format' };
    }

    const user = await userService.findByUserId(drexoraUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    if (normalizedNewEmail === user.profile.email) {
      throw { status: 400, message: 'New email address must be different from current email' };
    }

    const isCurrentCorrect = await verifyPassword(currentPassword, user.security.passwordHash);
    if (!isCurrentCorrect) {
      throw { status: 400, message: 'Current password is incorrect' };
    }

    // Check if new email already belongs to another user
    const existing = await userService.findByEmail(normalizedNewEmail);
    if (existing) {
      throw { status: 409, message: 'This email address is already in use by another account' };
    }

    await userService.setPendingEmail(drexoraUserId, normalizedNewEmail);

    const { rawToken } = await tokenService.createToken(
      'emailChangeTokens',
      { drexoraUserId, newEmail: normalizedNewEmail },
      EMAIL_CHANGE_TOKEN_TTL
    );

    await emailService.sendEmailChangeVerification(normalizedNewEmail, rawToken, user.profile.fullName);

    return { message: `Verification email sent to ${normalizedNewEmail}. Please confirm to complete the email change.` };
  }

  /**
   * Confirm Email Change Flow
   */
  async confirmEmailChange(rawToken) {
    if (!rawToken) throw { status: 400, message: 'Token is required' };

    const result = await tokenService.verifyAndConsumeToken('emailChangeTokens', rawToken);
    if (!result.valid) {
      throw { status: 400, message: 'Invalid or expired email change verification link' };
    }

    const { drexoraUserId, newEmail } = result.data;
    await userService.updatePrimaryEmail(drexoraUserId, newEmail);

    return { message: 'Your primary account email address has been updated successfully.' };
  }
}

module.exports = new AuthService();
