# Drexora Account & Platform Layer — Complete Identity System

A custom-built, standalone core account, identity, and application platform built from scratch using **Node.js**, **Express.js**, **Vanilla HTML/CSS/JS**, **Firebase Realtime Database**, and **Resend**.

---

## 📚 Continue with Drexora Integration Documentation

To integrate **Continue with Drexora** into another web or mobile application (internal product or third-party) without modifying Drexora Account source code, consult the official documentation in the `docs/` folder:

* 📖 **[Official Integration Guide](docs/continue-with-drexora.md):** Complete developer guide covering architecture, PKCE SSO flow, callbacks, database mapping, and code examples.
* 🤖 **[Master AI Prompt](docs/continue-with-drexora-ai-prompt.md):** Reusable prompt to instruct another coding AI (Jules, Cursor, ChatGPT, etc.) to integrate Drexora SSO into any target repository.
* ⚡ **[Quick-Start Checklist](docs/continue-with-drexora-quick-start.md):** Concise 10-step checklist for experienced developers.
* ✅ **[Integration Checklist](docs/continue-with-drexora-checklist.md):** Phase-by-phase verification checklist.
* 🛠️ **[Technical Protocol & API Reference](docs/continue-with-drexora-reference.md):** OIDC Discovery, JWKS, token exchange, UserInfo, and revocation API specs.

---

## 🌟 Key Features

1. **Permanent Drexora User ID**: Each account receives an immutable, secure, non-sequential user ID (e.g., `dx_8f72abc123`) that remains constant even if the user changes their email address.
2. **Developer & Application Portal**: Self-service application management allowing developers to register public/confidential applications, configure HTTPS redirect URIs, manage allowed scopes, rotate client secrets, and view personalized integration guides.
3. **Connected Applications & Consent Revocation**: Logged-in users can view all authorized applications, inspect granted permissions, and revoke access instantly with real-time token invalidation.
4. **Product Registry, Product Access & Entitlements**: Platform foundation supporting products (`Drexora Support`, `Handles`, `Drexora AI`, `Drexora Transfer`, `Drexora Guard`), user product access, entitlements, and subscription structures.
5. **Security Audit Logging & Notifications**: Sanitized audit trail (`auditLogs/`) recording non-sensitive security events and sending automated security alerts via Resend.
6. **Safe Account Deletion**: Password-confirmed account closure workflow that revokes all active device sessions, OAuth tokens, and app permissions while anonymizing user identity.
2. **Custom Backend Authentication**:
   - Argon2id password hashing with bcrypt fallback.
   - Normalized email handling & duplicate prevention.
   - Single-use, cryptographically secure hashed verification tokens.
3. **Multi-Device Session System**:
   - Secure server-controlled sessions stored in Firebase.
   - HttpOnly, SameSite=Lax authentication cookies (JavaScript cannot access session tokens).
   - Real-time device/browser parsing and IP tracking.
   - Ability to view all active sessions, revoke individual device sessions, or log out all other devices.
4. **Security & Account Control**:
   - Account status enforcement (`active`, `email_unverified`, `suspended`, `disabled`).
   - Forgot password & reset password workflows with single-use reset links.
   - Authenticated password change with automated session revocation.
   - Safe email change request flow requiring verification of the new email address.
   - Helmet HTTP security headers, CORS, rate limiting, and generic error messaging to prevent user enumeration.
5. **Transactional Email Service**:
   - Powered by Resend API with clean, professional HTML email templates.
6. **Render Deployment Ready**:
   - `GET /health` endpoint included.
   - Supports multiline environment variables (such as Firebase private keys).

---

## 📁 Repository Architecture

```text
DREXORA-ACCOUNT/
├── .env.example              # Environment variables template
├── package.json              # App configuration & dependencies
├── README.md                 # System overview & deployment guide
├── public/                   # Frontend UI (Vanilla HTML/CSS/JS)
│   ├── css/
│   │   └── style.css         # Clean, modern CSS design system
│   ├── js/
│   │   └── app.js            # Client API wrapper & page handlers
│   ├── index.html            # Landing / welcome page
│   ├── login.html            # Sign in page
│   ├── register.html         # Account registration page
│   ├── verify-email.html     # Email verification handler & resend form
│   ├── forgot-password.html  # Password reset request page
│   ├── reset-password.html   # New password submission page
│   ├── account.html          # Profile overview & name updates
│   ├── security.html         # Password & email change settings
│   └── sessions.html         # Active devices & session management
├── src/                      # Express Backend Architecture
│   ├── server.js             # Express application entry point
│   ├── config/               # Environment configuration loader
│   ├── controllers/          # API endpoint logic (Auth & Account)
│   ├── db/                   # Firebase Admin Database abstraction
│   ├── middleware/           # Auth & rate-limiting middleware
│   ├── routes/               # API route declarations
│   ├── services/             # Core business logic (User, Auth, Session, Token, Email)
│   └── utils/                # Password, ID generator & validator utilities
└── tests/
    └── account.test.js       # Complete automated test suite
```

---

## 🗄️ Firebase Database Structure

```text
users/
  {drexoraUserId}/
    profile/
      fullName: string
      email: string
      pendingEmail: string | null
    security/
      passwordHash: string
      passwordLastChangedAt: timestamp
    accountStatus: 'active' | 'email_unverified' | 'suspended' | 'disabled'
    emailVerified: boolean
    metadata/
      createdAt: timestamp
      lastLoginAt: timestamp

emailIndex/
  {encodedEmail}/
    drexoraUserId: string

sessions/
  {hashedSessionId}/
    drexoraUserId: string
    createdAt: timestamp
    lastActivity: timestamp
    expiresAt: timestamp
    revoked: boolean
    ipAddress: string
    deviceInfo: { browser, os, device, userAgent }

userSessions/
  {drexoraUserId}/
    {hashedSessionId}/
      createdAt: timestamp
      lastActivity: timestamp

verificationTokens/
  {hashedToken}/
    drexoraUserId: string
    email: string
    expiresAt: timestamp
    used: boolean

passwordResetTokens/
  {hashedToken}/
    drexoraUserId: string
    email: string
    expiresAt: timestamp
    used: boolean

emailChangeTokens/
  {hashedToken}/
    drexoraUserId: string
    newEmail: string
    expiresAt: timestamp
    used: boolean
```

---

## 🔌 API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Health check endpoint for uptime monitors / Render |
| `POST` | `/api/auth/register` | Register new Drexora account |
| `POST` | `/api/auth/login` | Authenticate user & issue HttpOnly session cookie |
| `POST` | `/api/auth/verify-email` | Verify account email address with single-use token |
| `POST` | `/api/auth/resend-verification` | Request a new verification link |
| `POST` | `/api/auth/forgot-password` | Request password reset email |
| `POST` | `/api/auth/reset-password` | Reset password using valid reset token |
| `POST` | `/api/auth/confirm-email-change` | Confirm and activate new email address |

### Protected Endpoints (Requires Valid Session)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Retrieve current authenticated user profile |
| `POST` | `/api/auth/logout` | Revoke current device session & clear cookie |
| `POST` | `/api/auth/logout-all` | Revoke all device sessions for the account |
| `POST` | `/api/auth/change-password` | Change password with current password verification |
| `POST` | `/api/auth/request-email-change` | Initiate primary email address change |
| `GET` | `/api/account/profile` | Read account profile |
| `PATCH` | `/api/account/profile` | Update profile information (e.g. full name) |
| `GET` | `/api/account/sessions` | List active sessions & devices |
| `DELETE` | `/api/account/sessions/:id` | Revoke specific session ID |
| `POST` | `/api/account/sessions/revoke-others` | Revoke all other active device sessions |
| `GET` | `/api/account/connected-apps` | List authorized applications and granted permissions |
| `DELETE` | `/api/account/connected-apps/:id` | Revoke application access & invalidate tokens |
| `POST` | `/api/account/delete` | Permanently delete user account with password verification |
| `GET` | `/api/developer/scopes` | List global platform scope registry |
| `GET` | `/api/developer/applications` | List applications owned by authenticated user |
| `POST` | `/api/developer/applications` | Register a new application |
| `GET` | `/api/developer/applications/:id` | View application details (strict ownership check) |
| `PATCH` | `/api/developer/applications/:id` | Update application configuration |
| `POST` | `/api/developer/applications/:id/rotate-secret` | Rotate confidential client secret |
| `DELETE` | `/api/developer/applications/:id` | Disable owned application |
| `GET` | `/api/platform/products` | List registered platform products |
| `GET` | `/api/platform/my-access` | View user product access, entitlements, and subscriptions |

---

## 🔑 Environment Variables Required

Create a `.env` file based on `.env.example`:

```env
PORT=3000
NODE_ENV=production
APP_URL=https://your-drexora-app.onrender.com

SESSION_SECRET=a_very_long_secure_random_secret_string
SESSION_MAX_AGE_DAYS=14

FIREBASE_DATABASE_URL=https://drexora-account-default-rtdb.firebaseio.com
FIREBASE_PROJECT_ID=drexora-account
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-xxxxx@drexora-account.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYOUR_KEY_HERE\n-----END PRIVATE KEY-----\n"

RESEND_API_KEY=re_123456789
EMAIL_FROM=Drexora Account <no-reply@drexora.com>

RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
LOGIN_RATE_LIMIT_MAX=10
```

---

## 🧪 Testing

Run the automated test suite locally:

```bash
npm test
```

All unit and integration tests covering registration, login, verification, multi-device session revocation, password reset, account status enforcement, and security controls will execute using Node's native test runner.

---

## 🚀 Deployment Instructions (Render)

1. Create a **New Web Service** on [Render](https://render.com/).
2. Connect your Git repository.
3. Configure the service parameters:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. Add all required **Environment Variables** in the Render Dashboard.
   *Note*: When entering `FIREBASE_PRIVATE_KEY` on Render, ensure newlines (`\n`) are either formatted as a multiline string or handled with `replace(/\\n/g, '\n')` (handled automatically by `src/config/index.js`).
5. Render will automatically monitor the `GET /health` endpoint for health checks.
