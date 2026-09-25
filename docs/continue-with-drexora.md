# Official Integration Guide: Continue with Drexora

Welcome to the official developer integration guide for **Continue with Drexora**. This guide explains how to add Drexora Single Sign-On (SSO) and OpenID Connect (OIDC) identity verification to your application without modifying any Drexora Account source code.

---

## 1. Overview

**Drexora Account** functions as an independent, centralized Identity Provider (IdP). It allows users to authenticate using a single account across internal Drexora products (`drexora_product`) and external third-party web and mobile applications (`external_application`).

### What Drexora Account Handles:
* User registration, email verification (8-digit code), login, password resets, and session security.
* Single Sign-On (SSO) authentication and scope-based user consent.
* Issuing single-use authorization codes, Bearer access tokens, and signed OIDC ID Tokens (`HS256`).
* UserInfo claims lookup and token revocation (`RFC 7009`).

### What Your Application Handles:
* Storing your assigned `client_id` and `client_secret` (for confidential server applications) in server-side environment variables.
* Initiating the SSO redirect flow with PKCE (`S256`) and state verification.
* Receiving the authorization code on your callback URL and exchanging it for tokens via backend HTTP request.
* Mapping the permanent Drexora User ID (`sub`) to your application's local user records.
* Managing your application's local session cookies or tokens.

### Data Model Architecture
```text
User
  │
  ▼
Your Application ("Continue with Drexora")
  │
  ▼
Drexora Account IdP (https://drexora-account.onrender.com)
  │
  ├── 1. Authentication (Login / Consent)
  ├── 2. Authorization Code Issued
  │
  ▼
Your Application Callback (/oauth/callback)
  │
  ├── 3. Token Exchange (/oauth/token)
  ├── 4. UserInfo Fetch (/oauth/userinfo)
  │
  ▼
Your Local Application Database (Maps sub -> local_user_id)
```

Your application retains complete control over its database, business logic, subscriptions, and local user sessions.

---

## 2. What I Need Before Integrating

### Information Obtained from Drexora Account
* **Issuer URL:** `https://drexora-account.onrender.com` (or `http://localhost:3000` during local development)
* **OIDC Discovery URL:** `https://drexora-account.onrender.com/.well-known/openid-configuration`
* **Authorization Endpoint:** `https://drexora-account.onrender.com/oauth/authorize`
* **Token Endpoint:** `https://drexora-account.onrender.com/oauth/token`
* **UserInfo Endpoint:** `https://drexora-account.onrender.com/oauth/userinfo`
* **Revocation Endpoint:** `https://drexora-account.onrender.com/oauth/revoke`
* **JWKS URL:** `https://drexora-account.onrender.com/.well-known/jwks.json`
* **Client ID (`client_id`):** Generated upon application registration (e.g., `dx_client_a1b2c3d4e5f6`).
* **Client Secret (`client_secret`):** Generated for confidential backend applications (shown once upon creation/rotation).
* **Allowed Scopes:** Permitted scopes assigned during registration (`openid`, `profile`, `email`).

### Information You Must Configure Inside Your Application
* **Redirect URI (`redirect_uri`):** The exact callback URL on your domain (e.g., `https://yourapp.com/auth/drexora/callback`).
* **PKCE Verifier & State Generator:** Cryptographically secure random string generators.

---

## 3. Registering a New Application

Applications are onboarded dynamically using the Drexora Account Developer Portal.

### Onboarding Steps:
1. Log in to your Drexora Account and navigate to **Developer Portal** (`/developer.html`).
2. Click **+ Register New App**.
3. Fill in basic information:
   * **Application Name:** e.g., `Acme Web Portal`
   * **Description:** e.g., `Acme Cloud Management Portal`
   * **Website URL:** e.g., `https://yourapp.com`
   * **Logo Image URL:** e.g., `https://yourapp.com/logo.png`
   * **Application Type:** Select `External Application` or `Drexora Product`.
   * **Client Type:**
     * `Public`: For Single Page Apps (SPA), Mobile, or Desktop apps where secrets cannot be protected. Uses PKCE (`S256`).
     * `Confidential`: For backend server applications (Node, Python, Go, PHP) that can safely store `client_secret`.
   * **Redirect URIs:** Enter exact callback URLs (one per line).
   * **Allowed Scopes:** Check requested permissions (`openid`, `profile`, `email`).
4. Click **Register Application**.
5. **Copy Credentials:**
   * Copy your `clientId`.
   * If client type is `confidential`, copy the generated `client_secret` immediately. It is stored as a secure hash and will **never** be displayed again.

---

## 4. Redirect URI Requirements

Every redirect URI provided during authorization requests must match one of your application's registered redirect URIs **character-for-character**.

### Rules & Validation:
* **No Wildcards:** Arbitrary wildcards (`*`) or unregistered subdomains are strictly rejected.
* **No Fragments:** Redirect URIs must not contain fragment identifiers (`#`).
* **Scheme Requirement:** Production redirect URIs must use `https://`. `http://` is allowed only for `localhost` or `127.0.0.1` during development.
* **Exact Matching:** `https://yourapp.com/callback` and `https://yourapp.com/callback/` are treated as different URIs.

#### Example Configuration:
```text
Development:  http://localhost:3000/auth/drexora/callback
Production:   https://yourapp.com/auth/drexora/callback
```

---

## 5. OAuth 2.0 / OpenID Connect Flow

Drexora Account implements standard Authorization Code Flow with PKCE (`S256`):

1. **User Clicks "Continue with Drexora":**
   Your application generates a random `state` and a PKCE `code_verifier`. It computes `code_challenge = base64url(sha256(code_verifier))`.
2. **Redirect to Authorization Endpoint:**
   User is redirected to `GET /oauth/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, and `code_challenge_method=S256`.
3. **Authentication & Consent:**
   Drexora Account authenticates the user, verifies email status, and presents the dynamic consent screen.
4. **Authorization Code Issued:**
   Drexora Account redirects back to your `redirect_uri` with `?code=dx_code_...&state=YOUR_STATE`.
5. **Token Exchange (Backend):**
   Your backend sends a `POST /oauth/token` request with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` (and `client_secret` if confidential).
6. **Tokens Received:**
   Drexora Account returns `access_token` and signed OIDC `id_token` (JWT signed via `HS256`).
7. **Identity Lookup:**
   Your backend calls `GET /oauth/userinfo` with header `Authorization: Bearer <access_token>` to retrieve profile claims (`sub`, `name`, `email`, `email_verified`).
8. **Local Session Created:**
   Your application matches `sub` to a local user record and issues its own secure session cookie.

---

## 6. Continue with Drexora Button

Add a button on your login/registration UI:

```html
<button id="drexora-sso-btn" class="sso-button">
  Continue with Drexora
</button>

<script>
  document.getElementById('drexora-sso-btn').addEventListener('click', async () => {
    // 1. Generate random PKCE verifier and state
    const verifier = generateRandomString(64);
    const state = generateRandomString(24);
    const challenge = await calculateSHA256Base64Url(verifier);

    // 2. Store verifier and state in browser session
    sessionStorage.setItem('drexora_pkce_verifier', verifier);
    sessionStorage.setItem('drexora_oauth_state', state);

    // 3. Build authorization URL targeting Drexora IdP
    const idpBaseUrl = 'https://drexora-account.onrender.com';
    const authUrl = new URL('/oauth/authorize', idpBaseUrl);
    authUrl.searchParams.set('client_id', 'YOUR_CLIENT_ID');
    authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/auth/drexora/callback');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // 4. Redirect browser
    window.location.href = authUrl.toString();
  });
</script>
```

---

## 7. Callback Handling

On your callback route (`/auth/drexora/callback`):

1. **Verify `state`:** Confirm `query.state` matches `sessionStorage.getItem('drexora_oauth_state')`.
2. **Retrieve `code_verifier`:** Extract `sessionStorage.getItem('drexora_pkce_verifier')`.
3. **Execute Token Exchange on Backend:**
   Send `POST https://drexora-account.onrender.com/oauth/token`:
   ```json
   {
     "grant_type": "authorization_code",
     "code": "dx_code_RECEIVED_IN_QUERY",
     "redirect_uri": "https://yourapp.com/auth/drexora/callback",
     "client_id": "YOUR_CLIENT_ID",
     "client_secret": "YOUR_CLIENT_SECRET",
     "code_verifier": "RETRIEVED_PKCE_VERIFIER"
   }
   ```
4. **Fetch UserInfo Claims:**
   Send `GET https://drexora-account.onrender.com/oauth/userinfo` with `Authorization: Bearer <access_token>`.
5. **Extract Immutable User ID:** Extract claim `sub` (e.g. `dx_8f72abc123`).
6. **Create Local Application Session:** Link `sub` to your local database user and issue an HttpOnly, Secure session cookie.

---

## 8. User Identity Model

The central identity key is `sub` (Drexora User ID, starting with `dx_`).

```text
Drexora User ID (sub: "dx_8f72abc123")
          │
          ▼
Your Local Database User Record (local_id: 1042, drexora_sub: "dx_8f72abc123")
```

### Critical Identity Rules:
* **Never use email as the primary key:** Users can change their email address in Drexora Account, but their `drexoraUserId` (`sub`) remains immutable forever.
* **Safe Account Linking:** Do NOT automatically merge existing local accounts based solely on matching email strings unless the user verifies ownership by logging in with their existing local password first.

---

## 9. Database Integration

You do **NOT** share a database with Drexora Account. Keep your existing database schema and add a single column:

```sql
ALTER TABLE users ADD COLUMN drexora_sub VARCHAR(64) UNIQUE;
```

### Login / Signup Handler Pseudo-code:
```js
let user = await db.findUserByDrexoraSub(userInfo.sub);

if (!user) {
  // First-time SSO user: create local account
  user = await db.createUser({
    drexoraSub: userInfo.sub,
    email: userInfo.email,
    name: userInfo.name
  });
}

// Issue local session
createLocalSessionCookie(res, user.id);
```

---

## 10. Environment Variables

Configure these variables in your application's `.env` file:

```env
# Drexora IdP Configuration
DREXORA_ISSUER_URL=https://drexora-account.onrender.com
DREXORA_CLIENT_ID=dx_client_YOUR_APP_ID
DREXORA_CLIENT_SECRET=dx_secret_YOUR_APP_SECRET
DREXORA_REDIRECT_URI=https://yourapp.com/auth/drexora/callback
DREXORA_SCOPES=openid profile email
```

* **Server-side only:** `DREXORA_CLIENT_SECRET` must NEVER be exposed to frontend JavaScript or committed to git repository.

---

## 11. Complete Node.js / Express Backend Example

```js
const express = require('express');
const fetch = require('node-fetch');
const app = express();

const DREXORA_BASE_URL = process.env.DREXORA_ISSUER_URL || 'https://drexora-account.onrender.com';
const CLIENT_ID = process.env.DREXORA_CLIENT_ID;
const CLIENT_SECRET = process.env.DREXORA_CLIENT_SECRET;
const REDIRECT_URI = process.env.DREXORA_REDIRECT_URI;

app.post('/api/auth/drexora/callback', express.json(), async (req, res) => {
  try {
    const { code, code_verifier } = req.body;

    // 1. Token Exchange
    const tokenRes = await fetch(`${DREXORA_BASE_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(400).json({ error: tokenData.error_description || 'Token exchange failed' });
    }

    // 2. Fetch UserInfo Profile
    const userInfoRes = await fetch(`${DREXORA_BASE_URL}/oauth/userinfo`, {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });

    const userInfo = await userInfoRes.json();
    if (!userInfoRes.ok) {
      return res.status(400).json({ error: 'Failed to fetch UserInfo claims' });
    }

    // 3. Find or Create Local User
    // const localUser = await findOrCreateUserBySub(userInfo.sub, userInfo);

    // 4. Return Local Application Session Token/Cookie
    res.json({ success: true, drexoraUserId: userInfo.sub, user: userInfo });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

---

## 12. Supported Scopes

| Scope | Granted Claims | Purpose |
| :--- | :--- | :--- |
| `openid` | `sub` | Required for OIDC identity verification & subject ID. |
| `profile` | `name` | Returns user's full name. |
| `email` | `email`, `email_verified` | Returns user's primary email address and verification flag. |
| `profile.read` | `name` | Read-only profile access. |
| `email.read` | `email`, `email_verified` | Read-only email access. |
| `account.read` | `sub`, `name`, `email` | Basic account metadata. |

---

## 13. Token Revocation & Logout

### Token Revocation
To revoke an access token when a user logs out:

```http
POST https://drexora-account.onrender.com/oauth/revoke
Content-Type: application/json

{
  "token": "dx_at_YOUR_ACCESS_TOKEN"
}
```

If a user revokes your application's access from their **Connected Apps** dashboard in Drexora Account, all tokens previously issued to your application are invalidated immediately. Subsequent `/oauth/userinfo` requests will return `401 Unauthorized`.
