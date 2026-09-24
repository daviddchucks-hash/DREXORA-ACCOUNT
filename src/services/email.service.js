const { Resend } = require('resend');
const config = require('../config');

class EmailService {
  constructor() {
    this.client = config.resend.apiKey ? new Resend(config.resend.apiKey) : null;
    this.from = config.resend.from;
  }

  async sendEmail({ to, subject, html, text }) {
    if (!this.client) {
      console.log(`[Email Mock/Disabled] To: ${to} | Subject: ${subject}`);
      console.log(`[Email Text Preview]:\n${text || 'HTML Content'}\n`);
      return { success: true, mocked: true };
    }

    try {
      const response = await this.client.emails.send({
        from: this.from,
        to,
        subject,
        html,
        text
      });
      return { success: true, response };
    } catch (error) {
      console.error('[Email Error] Failed to send email via Resend:', error);
      // Fail gracefully so application flow isn't crashed unexpectedly
      return { success: false, error: error.message };
    }
  }

  /**
   * Send Account Verification Email
   */
  async sendVerificationEmail(email, token, name) {
    const verifyUrl = `${config.appUrl}/verify-email.html?token=${token}`;
    const subject = 'Verify your Drexora Account email';
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background-color: #f9fafb; margin: 0; padding: 40px 20px; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 32px; }
          .logo { font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 24px; letter-spacing: -0.5px; }
          .btn { display: inline-block; background: #111827; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 500; font-size: 14px; margin-top: 16px; margin-bottom: 16px; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 32px; border-top: 1px solid #f3f4f6; padding-top: 16px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">Drexora Account</div>
          <p>Hello ${name || 'there'},</p>
          <p>Thank you for registering your Drexora Account. Please confirm your email address by clicking the button below:</p>
          <p><a href="${verifyUrl}" class="btn">Verify Email Address</a></p>
          <p style="font-size: 13px; color: #4b5563;">Or copy and paste this link into your browser:<br><a href="${verifyUrl}">${verifyUrl}</a></p>
          <p style="font-size: 13px; color: #6b7280;">This verification link will expire in 24 hours.</p>
          <div class="footer">
            If you did not create a Drexora Account, you can safely ignore this email.
          </div>
        </div>
      </body>
      </html>
    `;
    const text = `Hello ${name || 'there'},\n\nPlease verify your email for your Drexora Account by visiting:\n${verifyUrl}\n\nThis link will expire in 24 hours.`;

    return await this.sendEmail({ to: email, subject, html, text });
  }

  /**
   * Send Password Reset Email
   */
  async sendPasswordResetEmail(email, token, name) {
    const resetUrl = `${config.appUrl}/reset-password.html?token=${token}`;
    const subject = 'Reset your Drexora Account password';
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background-color: #f9fafb; margin: 0; padding: 40px 20px; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 32px; }
          .logo { font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 24px; letter-spacing: -0.5px; }
          .btn { display: inline-block; background: #111827; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 500; font-size: 14px; margin-top: 16px; margin-bottom: 16px; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 32px; border-top: 1px solid #f3f4f6; padding-top: 16px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">Drexora Account</div>
          <p>Hello ${name || 'there'},</p>
          <p>We received a request to reset your password. Click the button below to set a new password:</p>
          <p><a href="${resetUrl}" class="btn">Reset Password</a></p>
          <p style="font-size: 13px; color: #4b5563;">Or copy and paste this link into your browser:<br><a href="${resetUrl}">${resetUrl}</a></p>
          <p style="font-size: 13px; color: #6b7280;">This password reset link will expire in 1 hour.</p>
          <div class="footer">
            If you did not request a password reset, please secure your account immediately.
          </div>
        </div>
      </body>
      </html>
    `;
    const text = `Hello ${name || 'there'},\n\nTo reset your Drexora Account password, visit:\n${resetUrl}\n\nThis link will expire in 1 hour.`;

    return await this.sendEmail({ to: email, subject, html, text });
  }

  /**
   * Send Email Change Verification
   */
  async sendEmailChangeVerification(newEmail, token, name) {
    const verifyUrl = `${config.appUrl}/verify-email.html?action=email_change&token=${token}`;
    const subject = 'Confirm new email address for your Drexora Account';
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background-color: #f9fafb; margin: 0; padding: 40px 20px; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 32px; }
          .logo { font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 24px; letter-spacing: -0.5px; }
          .btn { display: inline-block; background: #111827; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 500; font-size: 14px; margin-top: 16px; margin-bottom: 16px; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 32px; border-top: 1px solid #f3f4f6; padding-top: 16px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">Drexora Account</div>
          <p>Hello ${name || 'there'},</p>
          <p>You requested to update your primary email address for Drexora Account to <strong>${newEmail}</strong>.</p>
          <p>Click below to verify this new email address:</p>
          <p><a href="${verifyUrl}" class="btn">Confirm Email Change</a></p>
          <p style="font-size: 13px; color: #4b5563;">Or link:<br><a href="${verifyUrl}">${verifyUrl}</a></p>
          <p style="font-size: 13px; color: #6b7280;">This link will expire in 2 hours.</p>
          <div class="footer">
            If you did not request this change, please ignore this email or change your password.
          </div>
        </div>
      </body>
      </html>
    `;
    const text = `Hello ${name || 'there'},\n\nConfirm your new primary email address (${newEmail}) by visiting:\n${verifyUrl}\n\nLink expires in 2 hours.`;

    return await this.sendEmail({ to: newEmail, subject, html, text });
  }

  /**
   * Send Security Alert Email
   */
  async sendSecurityAlert(email, title, message) {
    const subject = `[Security Alert] ${title}`;
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background-color: #f9fafb; margin: 0; padding: 40px 20px; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 32px; }
          .logo { font-size: 20px; font-weight: 700; color: #111827; margin-bottom: 24px; letter-spacing: -0.5px; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 32px; border-top: 1px solid #f3f4f6; padding-top: 16px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">Drexora Account</div>
          <h3>${title}</h3>
          <p>${message}</p>
          <div class="footer">
            This is an automated security notice from Drexora Account.
          </div>
        </div>
      </body>
      </html>
    `;
    return await this.sendEmail({ to: email, subject, html, text: `${title}\n\n${message}` });
  }
}

module.exports = new EmailService();
