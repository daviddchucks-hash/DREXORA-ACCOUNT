const userService = require('../services/user.service');
const sessionService = require('../services/session.service');

class AccountController {
  async getProfile(req, res, next) {
    try {
      const publicProfile = userService.toPublicProfile(req.user);
      res.json({ profile: publicProfile });
    } catch (error) {
      next(error);
    }
  }

  async updateProfile(req, res, next) {
    try {
      const updatedUser = await userService.updateProfile(req.user.drexoraUserId, req.body);
      res.json({
        message: 'Profile updated successfully',
        profile: userService.toPublicProfile(updatedUser)
      });
    } catch (error) {
      next(error);
    }
  }

  async getSessions(req, res, next) {
    try {
      const sessions = await sessionService.getUserSessions(req.user.drexoraUserId, req.rawSessionId);
      res.json({ sessions });
    } catch (error) {
      next(error);
    }
  }

  async revokeSession(req, res, next) {
    try {
      const targetSessionId = req.params.id;
      const success = await sessionService.revokeSession(req.user.drexoraUserId, targetSessionId);
      if (!success) {
        return res.status(404).json({ error: 'Session not found or already revoked' });
      }
      res.json({ message: 'Session revoked successfully' });
    } catch (error) {
      next(error);
    }
  }

  async revokeOtherSessions(req, res, next) {
    try {
      const count = await sessionService.revokeAllOtherSessions(req.user.drexoraUserId, req.rawSessionId);
      res.json({ message: `Successfully logged out ${count} other device(s)` });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AccountController();
