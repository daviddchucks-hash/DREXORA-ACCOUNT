const platformService = require('../services/platform.service');

class PlatformController {
  /**
   * GET /api/platform/products
   * Returns list of registered Drexora platform products
   */
  async getProducts(req, res, next) {
    try {
      const products = await platformService.getAllProducts();
      res.status(200).json({ products });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/platform/my-access
   * Returns authenticated user's product access, entitlements, and subscriptions
   */
  async getMyPlatformAccess(req, res, next) {
    try {
      const summary = await platformService.getUserPlatformSummary(req.user.drexoraUserId);
      res.status(200).json(summary);
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new PlatformController();
