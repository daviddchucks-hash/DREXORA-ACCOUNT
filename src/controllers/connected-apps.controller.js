const connectedAppsService = require('../services/connected-apps.service');

class ConnectedAppsController {
  /**
   * GET /api/account/connected-apps
   * List all connected applications for authenticated user
   */
  async getConnectedApps(req, res, next) {
    try {
      const apps = await connectedAppsService.getUserConnectedApps(req.user.drexoraUserId);
      res.status(200).json({ connectedApps: apps });
    } catch (error) {
      next(error);
    }
  }

  /**
   * DELETE /api/account/connected-apps/:clientId
   * Revoke access for a specific application
   */
  async revokeAppAccess(req, res, next) {
    try {
      const clientId = req.params.clientId;
      const result = await connectedAppsService.revokeConnectedApp(
        req.user.drexoraUserId,
        clientId,
        req.user.profile.email
      );
      res.status(200).json(result);
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }
}

module.exports = new ConnectedAppsController();
