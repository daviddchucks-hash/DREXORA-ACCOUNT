const db = require('../db/firebase');
const auditService = require('./audit.service');

const DEFAULT_PRODUCTS = [
  {
    productId: 'drexora_support',
    name: 'Drexora Support',
    description: 'Centralized customer support and ticket management system.',
    status: 'active',
    website: 'https://support.drexora.com'
  },
  {
    productId: 'drexora_handles',
    name: 'Handles',
    description: 'Universal handle and identity domain registry for Drexora users.',
    status: 'active',
    website: 'https://handles.drexora.com'
  },
  {
    productId: 'drexora_ai',
    name: 'Drexora AI',
    description: 'AI assistant and intelligent model suite integrated across products.',
    status: 'active',
    website: 'https://ai.drexora.com'
  },
  {
    productId: 'drexora_transfer',
    name: 'Drexora Transfer',
    description: 'Encrypted file transfer and secure data storage service.',
    status: 'active',
    website: 'https://transfer.drexora.com'
  },
  {
    productId: 'drexora_guard',
    name: 'Drexora Guard',
    description: 'Advanced threat defense, security monitoring, and identity security.',
    status: 'active',
    website: 'https://guard.drexora.com'
  }
];

class PlatformService {
  /**
   * Seeds default product registry records.
   */
  async seedProducts() {
    try {
      for (const prod of DEFAULT_PRODUCTS) {
        const existing = await db.get(`products/${prod.productId}`);
        if (!existing) {
          const now = Date.now();
          await db.set(`products/${prod.productId}`, {
            ...prod,
            createdAt: now,
            updatedAt: now
          });
        }
      }
    } catch (err) {
      console.warn('[Platform Service] Product registry seeding warning:', err.message);
    }
  }

  /**
   * Returns all registered products.
   */
  async getAllProducts() {
    await this.seedProducts();
    const prods = await db.get('products');
    if (!prods) return DEFAULT_PRODUCTS;
    return Object.values(prods);
  }

  /**
   * Returns a user's product access, entitlements, and subscriptions.
   */
  async getUserPlatformSummary(drexoraUserId) {
    if (!drexoraUserId) return { productAccess: [], entitlements: [], subscriptions: [] };

    const accessRecords = (await db.get(`productAccess/${drexoraUserId}`)) || {};
    const entitlementRecords = (await db.get(`entitlements/${drexoraUserId}`)) || {};
    const subscriptionRecords = (await db.get(`subscriptions/${drexoraUserId}`)) || {};

    return {
      productAccess: Object.values(accessRecords),
      entitlements: Object.values(entitlementRecords),
      subscriptions: Object.values(subscriptionRecords)
    };
  }

  /**
   * Grants or updates a user's access to a product.
   */
  async grantProductAccess(drexoraUserId, productId, status = 'active') {
    const now = Date.now();
    const accessData = {
      drexoraUserId,
      productId,
      status,
      createdAt: now,
      updatedAt: now
    };

    await db.set(`productAccess/${drexoraUserId}/${productId}`, accessData);

    await auditService.logEvent({
      event: 'platform.product_access.updated',
      userId: drexoraUserId,
      metadata: { productId, status }
    });

    return accessData;
  }

  /**
   * Sets or updates user entitlements for a product.
   */
  async setUserEntitlements(drexoraUserId, productId, entitlementsList = [], source = 'system') {
    const now = Date.now();
    const entitlementData = {
      drexoraUserId,
      productId,
      entitlements: Array.isArray(entitlementsList) ? entitlementsList : [entitlementsList],
      source,
      status: 'active',
      updatedAt: now
    };

    await db.set(`entitlements/${drexoraUserId}/${productId}`, entitlementData);
    return entitlementData;
  }

  /**
   * Creates or updates subscription record structure for user & product.
   */
  async setUserSubscription(drexoraUserId, productId, { planId, status = 'active', durationDays = 30 }) {
    const now = Date.now();
    const expiresAt = now + (durationDays * 24 * 60 * 60 * 1000);

    const subData = {
      drexoraUserId,
      productId,
      planId: planId || 'standard',
      status,
      startDate: now,
      renewalDate: expiresAt,
      expirationDate: expiresAt,
      updatedAt: now
    };

    await db.set(`subscriptions/${drexoraUserId}/${productId}`, subData);
    return subData;
  }
}

const service = new PlatformService();
service.seedProducts().catch(() => {});

module.exports = service;
