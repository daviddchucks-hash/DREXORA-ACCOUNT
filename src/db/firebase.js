const admin = require('firebase-admin');
const config = require('../config');

let dbInstance = null;
let isInMemoryFallback = false;

// In-memory fallback database for local testing or when Firebase credentials are not supplied
class MemoryDB {
  constructor() {
    this.store = {
      users: {},
      emailIndex: {}, // normalizedEmail -> userId
      sessions: {},
      userSessions: {},
      verificationTokens: {},
      passwordResetTokens: {},
      emailChangeTokens: {}
    };
  }

  _getByPathParts(parts) {
    let curr = this.store;
    for (const p of parts) {
      if (curr === undefined || curr === null || typeof curr !== 'object') return undefined;
      curr = curr[p];
    }
    return curr;
  }

  async get(path) {
    const parts = path.split('/').filter(Boolean);
    const val = this._getByPathParts(parts);
    if (val === undefined) return null;
    return JSON.parse(JSON.stringify(val));
  }

  async set(path, data) {
    const parts = path.split('/').filter(Boolean);
    let curr = this.store;
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts[i];
      if (!curr[p] || typeof curr[p] !== 'object') {
        curr[p] = {};
      }
      curr = curr[p];
    }
    curr[parts[parts.length - 1]] = JSON.parse(JSON.stringify(data));
  }

  async update(path, data) {
    const existing = (await this.get(path)) || {};
    if (typeof data === 'object' && data !== null) {
      for (const [k, v] of Object.entries(data)) {
        if (k.includes('/')) {
          await this.set(`${path}/${k}`, v);
        } else {
          existing[k] = v;
        }
      }
      if (!Object.keys(data).some(k => k.includes('/'))) {
        await this.set(path, existing);
      }
    } else {
      await this.set(path, data);
    }
  }

  async remove(path) {
    const parts = path.split('/').filter(Boolean);
    if (parts.length === 0) return;
    let curr = this.store;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!curr[parts[i]]) return;
      curr = curr[parts[i]];
    }
    delete curr[parts[parts.length - 1]];
  }
}

function initFirebase() {
  if (dbInstance) return dbInstance;

  const hasCredentials = config.firebase.projectId && config.firebase.clientEmail && config.firebase.privateKey;

  if (hasCredentials) {
    try {
      if (!admin.apps.length) {
        admin.initializeApp({
          credential: admin.credential.cert({
            projectId: config.firebase.projectId,
            clientEmail: config.firebase.clientEmail,
            privateKey: config.firebase.privateKey
          }),
          databaseURL: config.firebase.databaseURL
        });
      }
      dbInstance = admin.database();
      console.log('[Database] Connected to Firebase Realtime Database');
      return dbInstance;
    } catch (err) {
      console.warn('[Database] Firebase initialization failed, switching to in-memory store:', err.message);
    }
  } else {
    console.log('[Database] Firebase credentials not fully configured. Using in-memory store mode for development/testing.');
  }

  isInMemoryFallback = true;
  dbInstance = new MemoryDB();
  return dbInstance;
}

class DatabaseService {
  constructor() {
    this.db = initFirebase();
  }

  async get(path) {
    if (isInMemoryFallback) {
      return await this.db.get(path);
    }
    const snapshot = await this.db.ref(path).once('value');
    return snapshot.exists() ? snapshot.val() : null;
  }

  async set(path, data) {
    if (isInMemoryFallback) {
      return await this.db.set(path, data);
    }
    await this.db.ref(path).set(data);
  }

  async update(path, data) {
    if (isInMemoryFallback) {
      return await this.db.update(path, data);
    }
    await this.db.ref(path).update(data);
  }

  async remove(path) {
    if (isInMemoryFallback) {
      return await this.db.remove(path);
    }
    await this.db.ref(path).remove();
  }
}

module.exports = new DatabaseService();
