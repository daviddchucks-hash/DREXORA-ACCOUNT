const authService = require('../services/auth.service');
const sessionService = require('../services/session.service');
const userService = require('../services/user.service');
const config = require('../config');
const { cookieOptions } = require('../middleware/auth.middleware');

class AuthController {
  async register(req, res, next) {
    try {
      const result = await authService.register(req.body);
      res.status(201).json(result);
    } catch (error) {
      next(error);
    }
  }

  async verifyEmail(req, res, next) {
    try {
      const token = req.query.token || req.query.code || req.body.token || req.body.code;
      const result = await authService.verifyEmail(token);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async resendVerification(req, res, next) {
    try {
      const { email } = req.body;
      const result = await authService.resendVerificationEmail(email);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async login(req, res, next) {
    try {
      const { rawSessionId, user, session } = await authService.login(req.body, req);

      // Set HttpOnly, Secure cookie
      res.cookie(config.session.cookieName, rawSessionId, cookieOptions());

      res.json({
        message: 'Login successful',
        user,
        sessionId: session.sessionId
      });
    } catch (error) {
      next(error);
    }
  }

  async me(req, res, next) {
    try {
      res.json({
        user: userService.toPublicProfile(req.user),
        currentSessionId: req.session.sessionId
      });
    } catch (error) {
      next(error);
    }
  }

  async logout(req, res, next) {
    try {
      if (req.rawSessionId) {
        await sessionService.revokeSession(req.user.drexoraUserId, req.session.sessionId);
      }
      res.clearCookie(config.session.cookieName, cookieOptions());
      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      next(error);
    }
  }

  async logoutAll(req, res, next) {
    try {
      await sessionService.revokeAllUserSessions(req.user.drexoraUserId);
      res.clearCookie(config.session.cookieName, cookieOptions());
      res.json({ message: 'Logged out from all devices successfully' });
    } catch (error) {
      next(error);
    }
  }

  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;
      const result = await authService.requestPasswordReset(email);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async resetPassword(req, res, next) {
    try {
      const result = await authService.resetPassword(req.body);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async changePassword(req, res, next) {
    try {
      const result = await authService.changePassword(req.user.drexoraUserId, req.body, req.rawSessionId);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async requestEmailChange(req, res, next) {
    try {
      const result = await authService.requestEmailChange(req.user.drexoraUserId, req.body);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }

  async confirmEmailChange(req, res, next) {
    try {
      const token = req.query.token || req.query.code || req.body.token || req.body.code;
      const result = await authService.confirmEmailChange(token);
      res.json(result);
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AuthController();
