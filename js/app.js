/**
 * Drexora Account Client API & Frontend Application Logic
 */

// Clean URLs: Automatically strip .html extension in address bar on static hosts
if (typeof window !== 'undefined' && window.location && window.location.pathname.endsWith('.html')) {
  let cleanPath = window.location.pathname.slice(0, -5);
  if (cleanPath.endsWith('/index')) {
    cleanPath = cleanPath.slice(0, -6) || '/';
  }
  const cleanUrl = cleanPath + window.location.search + window.location.hash;
  window.history.replaceState(null, '', cleanUrl);
}

// Centralized API Base URL
const API_BASE_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? ''
  : 'https://api.drexxora.name.ng';

const API = {
  async req(endpoint, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    // Attach Bearer token from sessionStorage if present (Dual-Method Auth for Cross-Site Browsers)
    const storedToken = sessionStorage.getItem('drexora_token');
    if (storedToken && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${storedToken}`;
    }

    const config = {
      credentials: 'include', // Sends HttpOnly cross-origin cookie if browser permits
      headers,
      ...options
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api${endpoint}`, config);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        // If unauthenticated error (401), clear invalid token
        if (res.status === 401) {
          sessionStorage.removeItem('drexora_token');
        }
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
    sessionStorage.removeItem('drexora_token');
    window.location.href = 'login';
    return null;
  }
}

// Redirect if already logged in
async function redirectIfAuthenticated() {
  try {
    await API.get('/auth/me');
    window.location.href = 'account';
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
  sessionStorage.removeItem('drexora_token');
  window.location.href = 'login';
}

// Password Strength Checker Helper
function calculatePasswordStrength(password) {
  if (!password) return { level: 0, text: '', className: '' };

  const hasMinLength = password.length >= 8;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  let criteriaMet = 0;
  if (hasMinLength) criteriaMet++;
  if (hasLower) criteriaMet++;
  if (hasUpper) criteriaMet++;
  if (hasNumber) criteriaMet++;
  if (hasSpecial) criteriaMet++;

  if (!hasMinLength || criteriaMet <= 2) {
    return { level: 1, text: 'Weak', className: 'strength-weak' };
  } else if (criteriaMet === 3) {
    return { level: 2, text: 'Medium', className: 'strength-medium' };
  } else if (criteriaMet === 4) {
    return { level: 3, text: 'Strong', className: 'strength-strong' };
  } else {
    return { level: 4, text: 'Very Strong', className: 'strength-very-strong' };
  }
}

function initPasswordStrength(inputId) {
  const inputEl = document.getElementById(inputId);
  if (!inputEl) return;

  if (inputEl.dataset.hasStrengthMeter) return;
  inputEl.dataset.hasStrengthMeter = 'true';

  const container = document.createElement('div');
  container.className = 'password-strength-meter';
  container.style.display = 'none';
  container.innerHTML = `
    <div class="strength-bars">
      <div class="strength-bar"></div>
      <div class="strength-bar"></div>
      <div class="strength-bar"></div>
      <div class="strength-bar"></div>
    </div>
    <div class="strength-label">
      <span>Password strength</span>
      <span class="strength-text"></span>
    </div>
  `;

  inputEl.parentNode.insertBefore(container, inputEl.nextSibling);

  const textEl = container.querySelector('.strength-text');

  const updateStrength = () => {
    const val = inputEl.value;
    if (!val) {
      container.style.display = 'none';
      container.className = 'password-strength-meter';
      textEl.textContent = '';
      return;
    }

    container.style.display = 'block';
    const result = calculatePasswordStrength(val);
    container.className = `password-strength-meter ${result.className}`;
    textEl.textContent = result.text;
  };

  inputEl.addEventListener('input', updateStrength);
  if (inputEl.value) updateStrength();
}

// Auto-initialize on DOMReady / Load
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const initAll = () => {
    ['password', 'newPassword'].forEach(id => {
      initPasswordStrength(id);
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
}

// Logout All Devices Action
async function handleLogoutAll() {
  if (!confirm('Are you sure you want to log out from all devices?')) return;
  try {
    await API.post('/auth/logout-all');
  } catch (e) {
    // Ignore error
  }
  sessionStorage.removeItem('drexora_token');
  window.location.href = 'login';
}
