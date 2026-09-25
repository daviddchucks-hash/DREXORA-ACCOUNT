const { test, describe, before, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const supertest = require('supertest');
const app = require('../src/server');
const db = require('../src/db/firebase');
const config = require('../src/config');
const userService = require('../src/services/user.service');
const oauthService = require('../src/services/oauth.service');
const { verifyJwt } = require('../src/utils/jwt.util');
const crypto = require('crypto');

const request = supertest(app);

describe('Drexora OAuth 2.0 & OIDC SSO Integration Test Suite', () => {
  let userSessionCookie;
  let rawUserSessionId;
  let testUser;
  let publicClient;
  let confidentialClient;

  before(async () => {
    // 1. Register and verify a test user account
    const regRes = await request.post('/api/auth/register').send({
      fullName: 'Alice Smith',
      email: 'alice.oauth@example.com',
      password: 'SecurePassword123!',
      confirmPassword: 'SecurePassword123!'
    });

    testUser = await userService.findByEmail('alice.oauth@example.com');
    await userService.markEmailVerified(testUser.drexoraUserId);

    // Login user to obtain valid session cookie
    const loginRes = await request.post('/api/auth/login').send({
      email: 'alice.oauth@example.com',
      password: 'SecurePassword123!'
    });

    userSessionCookie = loginRes.headers['set-cookie'][0];
    rawUserSessionId = loginRes.body.token;

    // 2. Register a Public Client (SPA / PKCE)
    publicClient = await oauthService.registerClient({
      clientId: 'dx_client_public_test',
      clientType: 'public',
      appType: 'external_application',
      name: 'Public Test Single Page App',
      redirectUris: ['https://publicapp.example.com/oauth/callback'],
      allowedScopes: ['openid', 'profile', 'email'],
      status: 'active'
    });

    // 3. Register a Confidential Client (Server App)
    confidentialClient = await oauthService.registerClient({
      clientId: 'dx_client_confidential_test',
      clientType: 'confidential',
      appType: 'external_application',
      name: 'Confidential Backend App',
      redirectUris: ['https://serverapp.example.com/oauth/callback'],
      allowedScopes: ['openid', 'profile', 'email'],
      status: 'active'
    });
  });

  describe('1. Redirect URI Security Checks', () => {
    test('Valid registered redirect URI allows authorization', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid profile email',
          state: 'state_123',
          code_challenge: 'test_code_challenge_string',
          code_challenge_method: 'S256'
        });

      // Should redirect to consent screen or return callback URL if consented
      assert.equal(res.status, 302);
      assert.ok(res.headers.location.includes('/oauth-consent.html') || res.headers.location.includes('code='));
    });

    test('Unregistered / modified / malicious redirect URI must be rejected with 400', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://malicious-attacker.com/callback',
          response_type: 'code',
          scope: 'openid',
          state: 'state_hack'
        });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'invalid_request');
      assert.ok(res.body.error_description.includes('redirect_uri'));
    });

    test('Wrong redirect URI for a valid client is rejected', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://serverapp.example.com/oauth/callback', // redirect belongs to another client
          response_type: 'code',
          scope: 'openid'
        });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'invalid_request');
    });
  });

  describe('2. Authorization Code Flow & PKCE Enforcement', () => {
    let pkceVerifier;
    let pkceChallenge;
    let authCode;

    before(() => {
      pkceVerifier = crypto.randomBytes(32).toString('hex');
      pkceChallenge = crypto.createHash('sha256').update(pkceVerifier).digest('base64url');
    });

    test('Public client authorization missing code_challenge is rejected', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid'
        });

      assert.equal(res.status, 302);
      assert.ok(res.headers.location.includes('error=invalid_request'));
      assert.ok(res.headers.location.includes('code_challenge'));
    });

    test('Consent approval issues valid authorization code', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid profile email',
          state: 'state_pkce_test',
          code_challenge: pkceChallenge,
          code_challenge_method: 'S256',
          consent: 'approved'
        });

      assert.equal(res.status, 302);
      const redirectUrl = new URL(res.headers.location);
      authCode = redirectUrl.searchParams.get('code');
      assert.ok(authCode.startsWith('dx_code_'));
      assert.equal(redirectUrl.searchParams.get('state'), 'state_pkce_test');
    });

    test('Token exchange with wrong PKCE code_verifier is rejected', async () => {
      const res = await request.post('/oauth/token').send({
        grant_type: 'authorization_code',
        code: authCode,
        redirect_uri: 'https://publicapp.example.com/oauth/callback',
        client_id: publicClient.clientId,
        code_verifier: 'wrong_verifier_string'
      });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'invalid_grant');
    });

    test('Token exchange with valid PKCE code_verifier succeeds', async () => {
      // Generate a fresh authorization code for exchange test
      const freshCode = await oauthService.createAuthorizationCode({
        clientId: publicClient.clientId,
        drexoraUserId: testUser.drexoraUserId,
        redirectUri: 'https://publicapp.example.com/oauth/callback',
        scope: ['openid', 'profile', 'email'],
        codeChallenge: pkceChallenge,
        codeChallengeMethod: 'S256'
      });

      const res = await request.post('/oauth/token').send({
        grant_type: 'authorization_code',
        code: freshCode,
        redirect_uri: 'https://publicapp.example.com/oauth/callback',
        client_id: publicClient.clientId,
        code_verifier: pkceVerifier
      });

      assert.equal(res.status, 200);
      assert.ok(res.body.access_token.startsWith('dx_at_'));
      assert.equal(res.body.token_type, 'Bearer');
      assert.ok(res.body.id_token);

      // Verify ID Token JWT Claims
      const verified = verifyJwt(res.body.id_token, config.jwtSecret);
      assert.equal(verified.valid, true);
      assert.equal(verified.payload.sub, testUser.drexoraUserId); // Permanent Drexora User ID!
      assert.equal(verified.payload.aud, publicClient.clientId);
      assert.equal(verified.payload.name, 'Alice Smith');
      assert.equal(verified.payload.email, 'alice.oauth@example.com');
      assert.equal(verified.payload.email_verified, true);
    });

    test('Authorization code single-use requirement (replay attack protection)', async () => {
      const singleUseCode = await oauthService.createAuthorizationCode({
        clientId: publicClient.clientId,
        drexoraUserId: testUser.drexoraUserId,
        redirectUri: 'https://publicapp.example.com/oauth/callback',
        scope: ['openid'],
        codeChallenge: pkceChallenge,
        codeChallengeMethod: 'S256'
      });

      // First exchange -> succeeds
      const firstRes = await request.post('/oauth/token').send({
        grant_type: 'authorization_code',
        code: singleUseCode,
        redirect_uri: 'https://publicapp.example.com/oauth/callback',
        client_id: publicClient.clientId,
        code_verifier: pkceVerifier
      });
      assert.equal(firstRes.status, 200);

      // Second exchange (replay) -> must fail
      const secondRes = await request.post('/oauth/token').send({
        grant_type: 'authorization_code',
        code: singleUseCode,
        redirect_uri: 'https://publicapp.example.com/oauth/callback',
        client_id: publicClient.clientId,
        code_verifier: pkceVerifier
      });

      assert.equal(secondRes.status, 400);
      assert.equal(secondRes.body.error, 'invalid_grant');
    });
  });

  describe('3. UserInfo Endpoint & Scope Enforcement', () => {
    let openidToken;
    let fullProfileToken;

    before(async () => {
      const tokenRes1 = await oauthService.issueTokens({
        clientId: publicClient.clientId,
        drexoraUserId: testUser.drexoraUserId,
        scope: 'openid'
      });
      openidToken = tokenRes1.access_token;

      const tokenRes2 = await oauthService.issueTokens({
        clientId: publicClient.clientId,
        drexoraUserId: testUser.drexoraUserId,
        scope: 'openid profile email'
      });
      fullProfileToken = tokenRes2.access_token;
    });

    test('UserInfo with openid scope returns only permanent subject ID', async () => {
      const res = await request
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${openidToken}`);

      assert.equal(res.status, 200);
      assert.equal(res.body.sub, testUser.drexoraUserId);
      assert.equal(res.body.name, undefined);
      assert.equal(res.body.email, undefined);
    });

    test('UserInfo with profile and email scope returns full permitted identity', async () => {
      const res = await request
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${fullProfileToken}`);

      assert.equal(res.status, 200);
      assert.equal(res.body.sub, testUser.drexoraUserId);
      assert.equal(res.body.name, 'Alice Smith');
      assert.equal(res.body.email, 'alice.oauth@example.com');
      assert.equal(res.body.email_verified, true);
      assert.equal(res.body.passwordHash, undefined); // Never leak security credentials
    });

    test('Token revocation invalidates token for UserInfo requests', async () => {
      const revokeRes = await request.post('/oauth/revoke').send({ token: fullProfileToken });
      assert.equal(revokeRes.status, 200);

      const userInfoRes = await request
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${fullProfileToken}`);

      assert.equal(userInfoRes.status, 401);
      assert.equal(userInfoRes.body.error, 'invalid_token');
    });
  });

  describe('4. Account & Client Status Enforcement', () => {
    test('Disabled client application cannot initiate authorization', async () => {
      const disabledClient = await oauthService.registerClient({
        name: 'Disabled Application',
        redirectUris: ['https://disabledapp.example.com/callback'],
        status: 'disabled'
      });

      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: disabledClient.clientId,
          redirect_uri: 'https://disabledapp.example.com/callback',
          response_type: 'code'
        });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'invalid_client');
    });

    test('Suspended user account cannot authorize applications', async () => {
      // Suspend user account
      await userService.setAccountStatus(testUser.drexoraUserId, 'suspended');

      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'test_challenge',
          code_challenge_method: 'S256'
        });

      assert.equal(res.status, 302);
      assert.ok(res.headers.location.includes('error=access_denied'));
      assert.ok(res.headers.location.includes('suspended'));

      // Restore account status
      await userService.setAccountStatus(testUser.drexoraUserId, 'active');
    });
  });

  describe('5. Unauthenticated User Flow', () => {
    test('Unauthenticated user is redirected to login page with return_to parameter', async () => {
      const res = await request
        .get('/oauth/authorize')
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'test_challenge',
          code_challenge_method: 'S256'
        });

      assert.equal(res.status, 302);
      assert.ok(res.headers.location.includes('/login.html?return_to='));
    });
  });

  describe('6. Cookie Security & Callback Redirect Security', () => {
    test('Login sets HttpOnly, Secure session cookie and returns session token', async () => {
      const loginRes = await request.post('/api/auth/register').send({
        fullName: 'Bob CookieTest',
        email: 'bob.cookie@example.com',
        password: 'SecurePassword123!',
        confirmPassword: 'SecurePassword123!'
      });

      const user = await userService.findByEmail('bob.cookie@example.com');
      await userService.markEmailVerified(user.drexoraUserId);

      const res = await request.post('/api/auth/login').send({
        email: 'bob.cookie@example.com',
        password: 'SecurePassword123!'
      });

      assert.equal(res.status, 200);
      assert.ok(res.body.token);

      const setCookieHeader = res.headers['set-cookie'] ? res.headers['set-cookie'][0] : '';
      assert.ok(setCookieHeader.includes('drexora_sid='));
      assert.ok(setCookieHeader.toLowerCase().includes('httponly'));
      assert.ok(setCookieHeader.toLowerCase().includes('samesite=none') || setCookieHeader.toLowerCase().includes('samesite=lax'));
    });

    test('Authorization redirect target contains code and state, without leaking internal tokens', async () => {
      const res = await request
        .get('/oauth/authorize')
        .set('Cookie', userSessionCookie)
        .query({
          client_id: publicClient.clientId,
          redirect_uri: 'https://publicapp.example.com/oauth/callback',
          response_type: 'code',
          scope: 'openid',
          state: 'secure_state_99',
          code_challenge: 'test_challenge_99',
          code_challenge_method: 'S256',
          consent: 'approved'
        });

      assert.equal(res.status, 302);
      const redirectLocation = res.headers.location;
      assert.ok(redirectLocation.startsWith('https://publicapp.example.com/oauth/callback?code=dx_code_'));
      assert.ok(redirectLocation.includes('state=secure_state_99'));

      // Ensure no raw tokens or passwords in redirect URL
      assert.equal(redirectLocation.includes('sso_token'), false);
      assert.equal(redirectLocation.includes('access_token'), false);
      assert.equal(redirectLocation.includes('id_token'), false);
    });
  });
});
