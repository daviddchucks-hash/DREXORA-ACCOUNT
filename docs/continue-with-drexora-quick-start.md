# Quick-Start Checklist: Continue with Drexora Integration

This quick-start checklist summarizes the steps for experienced developers integrating **Continue with Drexora** into an existing or new application.

---

## ⚡ Quick-Start Steps

1. **Register Application:**
   Log in to Drexora Account, navigate to Developer Portal (`/developer.html`), and register your application.
2. **Configure Redirect URI:**
   Add exact callback URLs targeting your primary domain (e.g., `https://drexorasupport.name.ng/auth/drexora/callback` or `http://localhost:3000/callback`) to ensure local session cookies are set on the custom domain, avoiding cross-domain cookie isolation and SSO redirect loops.
3. **Select Allowed Scopes:**
   Select required scopes (`openid`, `profile`, `email`).
4. **Copy Credentials:**
   Copy `client_id` (and `client_secret` if confidential) into your server-side `.env` configuration.
5. **Add "Continue with Drexora" Button:**
   Add frontend button that generates random `state` + PKCE `code_verifier`, stores them in `sessionStorage`, computes PKCE `code_challenge`, and redirects to `${DREXORA_ISSUER_URL}/oauth/authorize`.
6. **Implement Callback Handler:**
   On your callback route, verify `state`, extract `code`, and send server-to-server POST request to `${DREXORA_ISSUER_URL}/oauth/token` with `code`, `code_verifier`, and `client_secret`.
7. **Fetch User Profile:**
   Call `GET ${DREXORA_ISSUER_URL}/oauth/userinfo` with `Authorization: Bearer <access_token>` to retrieve profile claims.
8. **Map Identity:**
   Store permanent `sub` (`drexoraUserId`) in your local user database column (`drexora_sub`).
9. **Issue Local Application Session:**
   Establish your own application's HttpOnly session cookie or JWT token on your primary domain. Never expose tokens in browser URLs (e.g. `/login?sso_token=...`).
10. **Implement Token Revocation on Logout:**
    Send POST request to `${DREXORA_ISSUER_URL}/oauth/revoke` with `{ token: access_token }` when the user logs out.
