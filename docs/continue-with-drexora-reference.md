# Technical Protocol & API Reference: Drexora Account

This document provides complete protocol and API endpoint specifications for **Drexora Account**.

---

## 📡 Base URLs & Discovery

* **Production IdP Issuer:** `https://drexora-account.onrender.com`
* **OIDC Discovery Document:** `GET https://drexora-account.onrender.com/.well-known/openid-configuration`
* **JWKS URI:** `GET https://drexora-account.onrender.com/.well-known/jwks.json`

---

## 🔑 Endpoints Reference

### 1. OpenID Connect Discovery
`GET /.well-known/openid-configuration`

#### Response:
```json
{
  "issuer": "https://drexora-account.onrender.com",
  "authorization_endpoint": "https://drexora-account.onrender.com/oauth/authorize",
  "token_endpoint": "https://drexora-account.onrender.com/oauth/token",
  "userinfo_endpoint": "https://drexora-account.onrender.com/oauth/userinfo",
  "revocation_endpoint": "https://drexora-account.onrender.com/oauth/revoke",
  "jwks_uri": "https://drexora-account.onrender.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email", "profile.read", "email.read", "account.read"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "grant_types_supported": ["authorization_code"]
}
```

---

### 2. Authorization Endpoint
`GET /oauth/authorize`

#### Query Parameters:
* `client_id` (required): Registered Client ID (`dx_client_...`).
* `redirect_uri` (required): Registered exact callback URL.
* `response_type` (required): Must be `code`.
* `scope` (required): Space-separated list of scopes (e.g. `openid profile email`).
* `state` (required): Cryptographically random string for CSRF mitigation.
* `code_challenge` (required for public clients): Base64url encoded SHA-256 hash of PKCE verifier.
* `code_challenge_method` (optional): PKCE method (`S256`).

#### Success Response:
`302 Redirect` to `redirect_uri?code=dx_code_...&state=YOUR_STATE`

---

### 3. Token Exchange Endpoint
`POST /oauth/token`

#### Headers:
`Content-Type: application/json`

#### Request Body:
```json
{
  "grant_type": "authorization_code",
  "code": "dx_code_RECEIVED_FROM_CALLBACK",
  "redirect_uri": "https://yourapp.com/auth/drexora/callback",
  "client_id": "dx_client_YOUR_APP_ID",
  "client_secret": "dx_secret_YOUR_APP_SECRET",
  "code_verifier": "YOUR_PKCE_VERIFIER"
}
```

#### Success Response (`200 OK`):
```json
{
  "access_token": "dx_at_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 4. UserInfo Endpoint
`GET /oauth/userinfo`

#### Headers:
`Authorization: Bearer dx_at_YOUR_ACCESS_TOKEN`

#### Success Response (`200 OK`):
```json
{
  "sub": "dx_8f72abc123",
  "name": "Jane Doe",
  "email": "jane.doe@example.com",
  "email_verified": true
}
```

---

### 5. Token Revocation Endpoint (RFC 7009)
`POST /oauth/revoke`

#### Headers:
`Content-Type: application/json`

#### Request Body:
```json
{
  "token": "dx_at_YOUR_ACCESS_TOKEN"
}
```

#### Success Response (`200 OK`):
```json
{
  "status": "success",
  "message": "Token revoked successfully"
}
```

---

## 🔒 Session Security & Callback Redirection Best Practices

* **Custom Domain Alignment:** Always configure `redirect_uri` to target the custom domain where the user will be logged in (e.g. `https://drexorasupport.name.ng/auth/drexora/callback`). Avoid registering hosting platform URLs (like `.onrender.com`) if the frontend is served on a custom domain, as browser cookie isolation will prevent the session cookie from reaching the custom domain.
* **Prohibit Credentials in URLs:** Never pass `sso_token`, access tokens, or session tokens in URL query strings (e.g. `/login?sso_token=...`).
* **Cross-Origin Session Handoff:** For separate backend/frontend origins, use a server-side short-lived, single-use ticket exchange endpoint (`POST /api/auth/exchange-ticket`) to set cross-origin HttpOnly cookies securely.

---

## 🛡️ Supported Scopes & Granted Claims

* `openid`: Grants `sub` (permanent Drexora User ID starting with `dx_`).
* `profile`: Grants `name`.
* `email`: Grants `email` and `email_verified`.
* `profile.read`: Grants `name`.
* `email.read`: Grants `email` and `email_verified`.
* `account.read`: Grants `sub`, `name`, `email`.

---

## ⚠️ Standard OAuth 2.0 Error Responses

Errors follow RFC 6749 standard JSON format:

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has already been used"
}
```

| Error Code | HTTP Status | Meaning |
| :--- | :--- | :--- |
| `invalid_request` | 400 | Missing parameter, unregistered `redirect_uri`, or invalid PKCE parameter. |
| `invalid_client` | 400 / 401 | Invalid `client_id` or incorrect `client_secret`. |
| `invalid_grant` | 400 | Expired, reused, or invalid authorization code or PKCE verifier. |
| `invalid_scope` | 400 | Requested scope is not allowed for this client. |
| `unauthorized_client` | 400 | Client application is disabled or revoked. |
| `access_denied` | 403 | User denied consent or user account is suspended/disabled. |
| `invalid_token` | 401 | Access token is invalid, expired, or revoked. |
