# Master AI Prompt: Add "Continue with Drexora" to Application

> **Instructions for the User:**
> Copy and paste the prompt below into another coding AI (such as Jules, Claude, ChatGPT, Cursor, GitHub Copilot, etc.) working on your target application repository to instruct it to integrate Drexora Account Single Sign-On (SSO) cleanly and securely.

---

```text
You are an expert software engineer task with integrating "Continue with Drexora" Single Sign-On (SSO) and OpenID Connect (OIDC) identity authentication into this application.

### INTEGRATION CREDENTIALS & CONFIGURATION
DREXORA ISSUER URL:
[PASTE DREXORA ISSUER URL HERE, e.g. https://drexora-account.onrender.com]

CLIENT ID:
[PASTE YOUR CLIENT ID HERE, e.g. dx_client_a1b2c3d4e5f6]

CLIENT SECRET (IF CONFIDENTIAL CLIENT):
[PASTE YOUR CLIENT SECRET HERE OR LEAVE BLANK IF PUBLIC CLIENT]

REDIRECT URI:
[PASTE YOUR REGISTERED REDIRECT URI HERE, e.g. https://yourapp.com/auth/drexora/callback]

ALLOWED SCOPES:
[PASTE REQUESTED SCOPES HERE, e.g. openid profile email]

DISCOVERY URL:
[PASTE DISCOVERY URL, e.g. https://drexora-account.onrender.com/.well-known/openid-configuration]

---

### MANDATORY DIRECTIVES & RULES
1. DO NOT modify or edit the Drexora Account identity server source code or database.
2. DO NOT replace this application's existing database. The application retains its own database, users table, sessions, and business data.
3. DO NOT use email address as the primary database key for user identification. You MUST store and map the immutable Drexora User ID (`sub`, starting with `dx_`) in a new or existing column (`drexora_sub` or `drexoraUserId`).
4. DO NOT expose client secrets in frontend JavaScript or HTML. Keep client secrets strictly in server-side environment variables.
5. ALWAYS implement PKCE (`S256`) and state verification to prevent Authorization Code Interception and Cross-Site Request Forgery (CSRF) attacks.
6. DO NOT automatically merge existing local accounts based solely on matching email addresses unless the user confirms ownership by authenticating with their local password.
7. DO NOT expose session tokens, access tokens, or credentials in browser URLs (e.g. `/login?sso_token=...`). Ensure the callback URL matches the primary application domain so session cookies are scoped to the custom domain, avoiding cross-domain cookie isolation and SSO redirect loops.

---

### STEP-BY-STEP EXECUTION PLAN

#### Step 1: Repository & Database Inspection
- Inspect the codebase to understand the existing user model, database ORM/SQL schema, and session management.
- Add a unique string column `drexora_sub` (or equivalent field) to the local users table/schema to store the immutable Drexora User ID (`sub`).

#### Step 2: Environment Configuration
- Add environment variables to `.env.example` and server config:
  `DREXORA_ISSUER_URL`
  `DREXORA_CLIENT_ID`
  `DREXORA_CLIENT_SECRET` (if confidential)
  `DREXORA_REDIRECT_URI`
  `DREXORA_SCOPES`

#### Step 3: Frontend "Continue with Drexora" Button
- Add a "Continue with Drexora" button to the login/signup views.
- When clicked, generate a cryptographically random `state` (24+ chars) and PKCE `code_verifier` (64+ chars).
- Compute `code_challenge = base64url(sha256(code_verifier))`.
- Store `state` and `code_verifier` in browser session storage (`sessionStorage`).
- Redirect the browser to:
  `${DREXORA_ISSUER_URL}/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(SCOPES)}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`

#### Step 4: Callback Route & Backend Token Exchange
- Create callback route handler on `${REDIRECT_URI}`.
- Verify `state` parameter matches stored state.
- Extract `code` from query parameters and retrieve stored `code_verifier`.
- Perform server-to-server POST request to `${DREXORA_ISSUER_URL}/oauth/token`:
  Body: `{ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier }`
- Extract `access_token` and `id_token`.

#### Step 5: UserInfo Claims & Local User Mapping
- Perform GET request to `${DREXORA_ISSUER_URL}/oauth/userinfo` with header `Authorization: Bearer ${access_token}`.
- Extract permanent `sub` claim (`dx_...`), `name`, and `email`.
- Find local user record by `drexora_sub === sub`.
- If local user does not exist, create a new local user record storing `drexora_sub: sub`, `email: email`, `name: name`.
- Create a secure, server-side local application session cookie for the user.

#### Step 6: Logout & Token Revocation
- When the user logs out from the application, revoke the access token by sending a POST request to `${DREXORA_ISSUER_URL}/oauth/revoke` with `{ token: access_token }`.
- Clear local application session cookies.

#### Step 7: Testing & Verification
- Test complete SSO authorization flow for a new user.
- Test complete SSO authorization flow for an existing user.
- Test CSRF state mismatch rejection.
- Test token revocation on logout.
- Provide a summary of implemented changes and verification results.
```
