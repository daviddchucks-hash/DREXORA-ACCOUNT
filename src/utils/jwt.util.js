const crypto = require('crypto');

/**
 * Encodes a JavaScript object or string into a URL-safe Base64 string.
 */
function base64UrlEncode(str) {
  const buf = typeof str === 'string' ? Buffer.from(str) : Buffer.from(JSON.stringify(str));
  return buf.toString('base64url');
}

/**
 * Decodes a URL-safe Base64 string back into JSON object or string.
 */
function base64UrlDecode(str) {
  const buf = Buffer.from(str, 'base64url');
  return JSON.parse(buf.toString('utf8'));
}

/**
 * Signs a payload as a HS256 JWT.
 * @param {object} payload
 * @param {string} secret
 * @param {object} options { expiresInSeconds: number }
 * @returns {string} Signed JWT token string
 */
function signJwt(payload, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const expiresInSeconds = options.expiresInSeconds || 3600;

  const fullPayload = {
    iat: now,
    exp: now + expiresInSeconds,
    ...payload
  };

  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(fullPayload);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('base64url');

  return `${dataToSign}.${signature}`;
}

/**
 * Verifies a HS256 JWT token signature and expiration.
 * @param {string} token
 * @param {string} secret
 * @returns {{ valid: boolean, payload?: object, error?: string }}
 */
function verifyJwt(token, secret) {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Token must be a non-empty string' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Malformed token structure' };
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(dataToSign)
    .digest('base64url');

  // Constant-time signature comparison to prevent timing attacks
  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSignature);

  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return { valid: false, error: 'Invalid token signature' };
  }

  let payload;
  try {
    payload = base64UrlDecode(encodedPayload);
  } catch (err) {
    return { valid: false, error: 'Failed to parse token payload' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) {
    return { valid: false, error: 'Token has expired' };
  }

  return { valid: true, payload };
}

/**
 * Verifies PKCE code_verifier against stored code_challenge and code_challenge_method.
 * @param {string} codeVerifier
 * @param {string} codeChallenge
 * @param {string} method ('S256' | 'plain')
 * @returns {boolean}
 */
function verifyCodeChallenge(codeVerifier, codeChallenge, method = 'S256') {
  if (!codeVerifier || !codeChallenge) return false;

  if (method === 'S256') {
    const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const bufA = Buffer.from(computed);
    const bufB = Buffer.from(codeChallenge);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  }

  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }

  return false;
}

module.exports = {
  signJwt,
  verifyJwt,
  verifyCodeChallenge
};
