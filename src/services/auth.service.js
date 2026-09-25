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

    // Generate single-use 8-digit email verification code
    const { rawToken: verificationCode } = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: user.drexoraUserId, email: normalizedEmail },
      VERIFICATION_TOKEN_TTL,
      true // isNumericCode
    );

    // Send verification email
    const emailRes = await emailService.sendVerificationEmail(normalizedEmail, verificationCode, user.profile.fullName);
    if (!emailRes.success) {
      console.warn(`[Registration Email Notice] User ${user.drexoraUserId} created, but email send failed: ${emailRes.error}`);
    }

    return {
      drexoraUserId: user.drexoraUserId,
      email: user.profile.email,
      accountStatus: user.accountStatus,
      message: emailRes.success
        ? 'Registration successful. An 8-digit verification code has been sent to your email.'
        : 'Registration successful. Note: Email sending failed; click Resend Verification to try again.'
    };
  }

  /**
   * Email Verification Flow (Supports 8-digit code or link token)
   */
  async verifyEmail(rawTokenOrCode) {
    if (!rawTokenOrCode || typeof rawTokenOrCode !== 'string') {
      throw { status: 400, message: 'Verification code or link is required' };
    }

    const trimmed = rawTokenOrCode.trim();
    const result = await tokenService.verifyAndConsumeToken('verificationTokens', trimmed);

    if (!result.valid) {
      if (result.reason === 'already_used') {
        throw { status: 400, message: 'This verification code or link has already been used. You can now log in.' };
      }
      if (result.reason === 'expired') {
        throw { status: 400, message: 'Verification code has expired. Enter your email below to request a new one.' };
      }
      throw { status: 400, message: 'Invalid verification code. Please check your email and try again.' };
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
      message: 'Email address verified successfully! You can now sign in to your Drexora Account.'
    };
  }

  /**
   * Resend Verification Email Flow
   */
  async resendVerificationEmail(email) {
    const genericResponse = { message: 'If an unverified account exists with that email address, a new 8-digit verification code has been sent.' };

    if (!email) {
      return genericResponse;
    }

    const normalizedEmail = normalizeEmail(email);
    if (!isValidEmail(normalizedEmail)) {
      return genericResponse;
    }

    const user = await userService.findByEmail(normalizedEmail);
    if (!user || user.emailVerified || user.accountStatus === 'suspended' || user.accountStatus === 'disabled') {
      return genericResponse;
    }

    const { rawToken: verificationCode } = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: user.drexoraUserId, email: normalizedEmail },
      VERIFICATION_TOKEN_TTL,
      true // isNumericCode
    );

    const emailRes = await emailService.sendVerificationEmail(normalizedEmail, verificationCode, user.profile.fullName);

    if (!emailRes.success) {
      console.warn(`[Resend Verification Notice] Email send failed: ${emailRes.error}`);
    }

    return genericResponse;
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

    if (!user) {
      throw { status: 401, message: 'Invalid email or password' };
    }

    const isMatch = await verifyPassword(password, user.security.passwordHash);
    if (!isMatch) {
      throw { status: 401, message: 'Invalid email or password' };
    }

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
        message: 'Your email address is not verified. Please check your email for the 8-digit verification code.'
      };
    }

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

    const result = await tokenService.verifyAndConsumeToken('passwordResetTokens', token.trim());
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

    const existing = await userService.findByEmail(normalizedNewEmail);
    if (existing) {
      throw { status: 409, message: 'This email address is already in use by another account' };
    }

    await userService.setPendingEmail(drexoraUserId, normalizedNewEmail);

    const { rawToken: verificationCode } = await tokenService.createToken(
      'emailChangeTokens',
      { drexoraUserId, newEmail: normalizedNewEmail },
      EMAIL_CHANGE_TOKEN_TTL,
      true
    );

    await emailService.sendEmailChangeVerification(normalizedNewEmail, verificationCode, user.profile.fullName);

    return { message: `Verification code sent to ${normalizedNewEmail}. Please enter the code to confirm the email change.` };
  }

  /**
   * Confirm Email Change Flow
   */
  async confirmEmailChange(rawCodeOrToken) {
    if (!rawCodeOrToken) throw { status: 400, message: 'Verification code or token is required' };

    const result = await tokenService.verifyAndConsumeToken('emailChangeTokens', rawCodeOrToken.trim());
    if (!result.valid) {
      throw { status: 400, message: 'Invalid or expired email change verification code' };
    }

    const { drexoraUserId, newEmail } = result.data;
    await userService.updatePrimaryEmail(drexoraUserId, newEmail);

    return { message: 'Your primary account email address has been updated successfully.' };
  }
}

module.exports = new AuthService();
