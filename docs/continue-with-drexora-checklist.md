# Integration Checklist: Continue with Drexora

Use this checklist to track your application's integration with **Continue with Drexora**:

---

### Phase 1: Registration & Credentials
- [ ] Application registered in Drexora Account Developer Portal (`/developer.html`).
- [ ] Appropriate Client Type selected (`Public` or `Confidential`).
- [ ] Application Type selected (`External Application` or `Drexora Product`).
- [ ] Exact Redirect URIs configured (e.g. `https://yourapp.com/auth/drexora/callback`).
- [ ] Allowed scopes configured (`openid profile email`).
- [ ] `DREXORA_CLIENT_ID` copied to server environment variables.
- [ ] `DREXORA_CLIENT_SECRET` (if confidential) copied to server environment variables (never committed or exposed to frontend).

---

### Phase 2: Frontend & SSO Initiation
- [ ] "Continue with Drexora" button added to UI.
- [ ] Random `state` string generated and verified.
- [ ] PKCE `code_verifier` generated and `code_challenge` (`S256`) computed.
- [ ] `state` and `code_verifier` stored safely in browser `sessionStorage`.
- [ ] User redirected to `${DREXORA_ISSUER_URL}/oauth/authorize` with correct query parameters.

---

### Phase 3: Callback & Token Exchange
- [ ] Callback route configured at registered `redirect_uri`.
- [ ] Callback handler verifies `state` parameter against stored state.
- [ ] Server-to-server POST request executed to `${DREXORA_ISSUER_URL}/oauth/token`.
- [ ] Single-use authorization `code`, `code_verifier`, `client_id`, and `client_secret` passed in token exchange body.
- [ ] `access_token` and signed OIDC `id_token` received successfully.

---

### Phase 4: Identity Mapping & Local Sessions
- [ ] UserInfo fetched from `${DREXORA_ISSUER_URL}/oauth/userinfo` with Bearer token.
- [ ] Immutable Drexora User ID (`sub`, e.g. `dx_8f72abc123`) extracted.
- [ ] Local user record created/matched using `drexora_sub` column (NOT email address).
- [ ] Secure local application session cookie established.

---

### Phase 5: Logout & Revocation
- [ ] Logout handler revokes access token at `${DREXORA_ISSUER_URL}/oauth/revoke`.
- [ ] Local application session invalidated on logout.
- [ ] Tested token revocation behavior when access is revoked from Drexora Account Connected Apps dashboard.

---

### Phase 6: Security & Production Audit
- [ ] No client secrets exposed in frontend JavaScript, HTML, or git commits.
- [ ] Production redirect URIs enforce HTTPS.
- [ ] No wildcard redirect URIs used.
- [ ] All 46+ repository unit and integration tests pass cleanly.
