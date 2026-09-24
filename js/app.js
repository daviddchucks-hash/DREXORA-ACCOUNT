/**
 * Drexora Account Client API & Frontend Application Logic
 */

// Centralized API Base URL
// When running locally on localhost, use relative '/api' endpoint.
// When hosted on GitHub Pages or external domain, point to Render production backend.
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? ''
  : 'https://drexora-account.onrender.com';

const API = {
  async req(endpoint, options = {}) {
    const config = {
      credentials: 'include', // Ensures cross-origin session cookies are sent
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api${endpoint}`, config);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'An error occurred. Please try again.');
      }
      return data;
    } catch (err) {
      throw err;
    }
  },

  get(endpoint) {
    return this.req(endpoint, { method: 'GET' });
  },

  post(endpoint, body) {
    return this.req(endpoint, { method: 'POST', body });
  },

  patch(endpoint, body) {
    return this.req(endpoint, { method: 'PATCH', body });
  },

  delete(endpoint) {
    return this.req(endpoint, { method: 'DELETE' });
  }
};

// UI Helper Functions
function showAlert(elementId, message, isSuccess = false) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `alert ${isSuccess ? 'alert-success' : 'alert-error'}`;
  el.style.display = 'block';
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.style.display = 'none';
}

function setLoading(buttonId, isLoading, originalText = 'Submit') {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  if (isLoading) {
    btn.disabled = true;
    btn.dataset.originalText = btn.textContent;
    btn.textContent = 'Please wait...';
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.originalText || originalText;
  }
}

// Global Auth Check for Protected Dashboard Pages
async function requireAuth() {
  try {
    const data = await API.get('/auth/me');
    return data.user;
  } catch (err) {
    window.location.href = 'login.html';
    return null;
  }
}

// Redirect if already logged in
async function redirectIfAuthenticated() {
  try {
    await API.get('/auth/me');
    window.location.href = 'account.html';
  } catch (err) {
    // User is guest, stay on auth page
  }
}

// Logout Action
async function handleLogout() {
  try {
    await API.post('/auth/logout');
  } catch (e) {
    // Ignore error
  }
  window.location.href = 'login.html';
}

// Logout All Devices Action
async function handleLogoutAll() {
  if (!confirm('Are you sure you want to log out from all devices?')) return;
  try {
    await API.post('/auth/logout-all');
  } catch (e) {
    // Ignore error
  }
  window.location.href = 'login.html';
}
