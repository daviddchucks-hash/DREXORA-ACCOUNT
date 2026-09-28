/**
 * Normalizes email address (lowercased, trimmed).
 * @param {string} email
 * @returns {string}
 */
function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

/**
 * Validates email format.
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const normalized = normalizeEmail(email);
  // Standard robust email regex
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return emailRegex.test(normalized) && normalized.length <= 254;
}

/**
 * Validates password strength.
 * Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number.
 * @param {string} password
 * @returns {{ valid: boolean, message?: string }}
 */
function validatePassword(password) {
  if (typeof password !== 'string') {
    return { valid: false, message: 'Password must be a string' };
  }
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long' };
  }
  if (password.length > 128) {
    return { valid: false, message: 'Password cannot exceed 128 characters' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  return { valid: true };
}

/**
 * Validates full name.
 * @param {string} name
 * @returns {boolean}
 */
function isValidName(name) {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return trimmed.length >= 2 && trimmed.length <= 100;
}

/**
 * Validates phone number format (international standard / E.164 or digits).
 * Allows leading +, digits, spaces, hyphens, parentheses. 7-20 digits.
 * @param {string} phone
 * @returns {boolean}
 */
function isValidPhone(phone) {
  if (typeof phone !== 'string') return false;
  const digitsOnly = phone.replace(/\D/g, '');
  if (digitsOnly.length < 7 || digitsOnly.length > 15) return false;
  const phoneRegex = /^\+?[0-9\s\-\(\)]{7,20}$/;
  return phoneRegex.test(phone.trim());
}

/**
 * Validates country string.
 * @param {string} country
 * @returns {boolean}
 */
function isValidCountry(country) {
  if (typeof country !== 'string') return false;
  const trimmed = country.trim();
  return trimmed.length >= 2 && trimmed.length <= 100;
}

/**
 * Validates date of birth string (YYYY-MM-DD or ISO format). Must be in past.
 * @param {string} dob
 * @returns {boolean}
 */
function isValidDateOfBirth(dob) {
  if (typeof dob !== 'string') return false;
  const trimmed = dob.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return false;
  const date = new Date(trimmed);
  if (isNaN(date.getTime())) return false;
  return date < new Date();
}

/**
 * Sanitizes input text to prevent basic XSS when echoing strings.
 * @param {string} str
 */
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

module.exports = {
  normalizeEmail,
  isValidEmail,
  validatePassword,
  isValidName,
  isValidPhone,
  isValidCountry,
  isValidDateOfBirth,
  sanitizeInput
};
