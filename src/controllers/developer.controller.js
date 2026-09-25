const developerService = require('../services/developer.service');

class DeveloperController {
  /**
   * GET /api/developer/scopes
   * Returns global list of valid scopes
   */
  async getScopes(req, res, next) {
    try {
      const scopes = developerService.getGlobalScopes();
      res.status(200).json({ scopes });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/developer/applications
   * Returns applications owned by authenticated user
   */
  async getApplications(req, res, next) {
    try {
      const ownerId = req.user.drexoraUserId;
      const apps = await developerService.getDeveloperApplications(ownerId);
      res.status(200).json({ applications: apps });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/developer/applications
   * Creates a new application owned by authenticated user
   */
  async createApplication(req, res, next) {
    try {
      const app = await developerService.createApplication(req.user, req.body);
      res.status(201).json({
        message: 'Application registered successfully',
        application: app
      });
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }

  /**
   * GET /api/developer/applications/:id
   * Retrieves specific application details (enforces ownership)
   */
  async getApplicationById(req, res, next) {
    try {
      const clientId = req.params.id;
      const ownerId = req.user.drexoraUserId;
      const app = await developerService.getDeveloperApplicationById(clientId, ownerId);
      res.status(200).json({ application: app });
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }

  /**
   * PATCH /api/developer/applications/:id
   * Updates an existing application (enforces ownership)
   */
  async updateApplication(req, res, next) {
    try {
      const clientId = req.params.id;
      const ownerId = req.user.drexoraUserId;
      const updated = await developerService.updateApplication(clientId, ownerId, req.body);
      res.status(200).json({
        message: 'Application updated successfully',
        application: updated
      });
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }

  /**
   * POST /api/developer/applications/:id/rotate-secret
   * Rotates confidential client secret (enforces ownership)
   */
  async rotateSecret(req, res, next) {
    try {
      const clientId = req.params.id;
      const ownerId = req.user.drexoraUserId;
      const result = await developerService.rotateClientSecret(clientId, ownerId);
      res.status(200).json(result);
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }

  /**
   * DELETE /api/developer/applications/:id
   * Disables an application (enforces ownership)
   */
  async deleteApplication(req, res, next) {
    try {
      const clientId = req.params.id;
      const ownerId = req.user.drexoraUserId;
      const result = await developerService.deleteApplication(clientId, ownerId);
      res.status(200).json(result);
    } catch (error) {
      if (error.error) {
        return res.status(error.status || 400).json(error);
      }
      next(error);
    }
  }
}

module.exports = new DeveloperController();
