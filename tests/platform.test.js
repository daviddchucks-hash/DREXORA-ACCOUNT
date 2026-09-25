const { test, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const app = require('../src/server');
const db = require('../src/db/firebase');
const userService = require('../src/services/user.service');
const developerService = require('../src/services/developer.service');
const connectedAppsService = require('../src/services/connected-apps.service');
const platformService = require('../src/services/platform.service');
const auditService = require('../src/services/audit.service');

describe('Drexora Platform Layer & Security Comprehensive Test Suite', () => {
  let devACookie = '';
  let devAToken = '';
  let devAUser = null;

  let devBCookie = '';
  let devBToken = '';
  let devBUser = null;

  let userCookie = '';
  let userToken = '';
  let userObj = null;

  before(async () => {
    // 1. Register Developer A
    const resA = await request(app)
      .post('/api/auth/register')
      .send({
        fullName: 'Developer Alice',
        email: 'developer.alice@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });
    assert.equal(resA.status, 201);
    const devAId = resA.body.drexoraUserId;
    await userService.markEmailVerified(devAId);

    // Login Developer A
    const loginA = await request(app)
      .post('/api/auth/login')
      .send({ email: 'developer.alice@example.com', password: 'Password123!' });
    assert.equal(loginA.status, 200);
    devAUser = loginA.body.user;
    devACookie = loginA.headers['set-cookie'];
    devAToken = loginA.body.token;

    // 2. Register Developer B
    const resB = await request(app)
      .post('/api/auth/register')
      .send({
        fullName: 'Developer Bob',
        email: 'developer.bob@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });
    assert.equal(resB.status, 201);
    const devBId = resB.body.drexoraUserId;
    await userService.markEmailVerified(devBId);

    const loginB = await request(app)
      .post('/api/auth/login')
      .send({ email: 'developer.bob@example.com', password: 'Password123!' });
    assert.equal(loginB.status, 200);
    devBUser = loginB.body.user;
    devBCookie = loginB.headers['set-cookie'];
    devBToken = loginB.body.token;

    // 3. Register Normal User Charlie
    const resU = await request(app)
      .post('/api/auth/register')
      .send({
        fullName: 'User Charlie',
        email: 'charlie.user@example.com',
        password: 'Password123!',
        confirmPassword: 'Password123!'
      });
    assert.equal(resU.status, 201);
    const userId = resU.body.drexoraUserId;
    await userService.markEmailVerified(userId);

    const loginU = await request(app)
      .post('/api/auth/login')
      .send({ email: 'charlie.user@example.com', password: 'Password123!' });
    assert.equal(loginU.status, 200);
    userObj = loginU.body.user;
    userCookie = loginU.headers['set-cookie'];
    userToken = loginU.body.token;
  });

  describe('1. Global Scope Registry', () => {
    test('GET /api/developer/scopes returns supported platform scopes', async () => {
      const res = await request(app)
        .get('/api/developer/scopes')
        .set('Cookie', devACookie);

      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.scopes));
      assert.ok(res.body.scopes.some(s => s.key === 'openid'));
      assert.ok(res.body.scopes.some(s => s.key === 'profile'));
      assert.ok(res.body.scopes.some(s => s.key === 'email'));
    });
  });

  describe('2. Developer Application Management & HPE Protection', () => {
    let appAId = '';

    test('Developer A registers a confidential application', async () => {
      const res = await request(app)
        .post('/api/developer/applications')
        .set('Cookie', devACookie)
        .send({
          name: "Alice's SaaS Portal",
          description: 'A confidential analytics tool',
          clientType: 'confidential',
          appType: 'external_application',
          redirectUris: ['http://localhost:3000/callback'],
          allowedScopes: ['openid', 'profile', 'email']
        });

      assert.equal(res.status, 201);
      assert.ok(res.body.application.clientId);
      assert.ok(res.body.application.clientSecret); // Secret returned once
      assert.equal(res.body.application.name, "Alice's SaaS Portal");
      appAId = res.body.application.clientId;
    });

    test('Developer A reads owned application details (secret is not exposed)', async () => {
      const res = await request(app)
        .get(`/api/developer/applications/${appAId}`)
        .set('Cookie', devACookie);

      assert.equal(res.status, 200);
      assert.equal(res.body.application.clientId, appAId);
      assert.equal(res.body.application.clientSecret, undefined);
      assert.equal(res.body.application.clientSecretHash, undefined);
    });

    test('Horizontal Privilege Escalation Protection: Developer B CANNOT view Developer A application', async () => {
      const res = await request(app)
        .get(`/api/developer/applications/${appAId}`)
        .set('Cookie', devBCookie);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'forbidden');
    });

    test('Horizontal Privilege Escalation Protection: Developer B CANNOT update Developer A application', async () => {
      const res = await request(app)
        .patch(`/api/developer/applications/${appAId}`)
        .set('Cookie', devBCookie)
        .send({ name: 'Hacked Application Name' });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'forbidden');
    });

    test('Horizontal Privilege Escalation Protection: Developer B CANNOT rotate Developer A client secret', async () => {
      const res = await request(app)
        .post(`/api/developer/applications/${appAId}/rotate-secret`)
        .set('Cookie', devBCookie);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'forbidden');
    });

    test('Developer A rotates client secret successfully', async () => {
      const res = await request(app)
        .post(`/api/developer/applications/${appAId}/rotate-secret`)
        .set('Cookie', devACookie);

      assert.equal(res.status, 200);
      assert.ok(res.body.clientSecret);
      assert.notEqual(res.body.clientSecret, '');
    });

    test('Unauthenticated user cannot access developer portal endpoints', async () => {
      const res = await request(app).get('/api/developer/applications');
      assert.equal(res.status, 401);
    });
  });

  describe('3. Connected Applications & Consent Revocation', () => {
    let testAppToken = '';

    test('Grant consent and issue OAuth tokens to Test App A for User Charlie', async () => {
      const crypto = require('crypto');
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

      const consentRes = await request(app)
        .get(`/oauth/authorize?client_id=dx_client_test_app&redirect_uri=http://localhost:3000/test-client/callback.html&response_type=code&scope=openid%20profile%20email&state=test_state_123&code_challenge=${challenge}&code_challenge_method=S256&consent=approved`)
        .set('Cookie', userCookie);

      assert.equal(consentRes.status, 302);
      const redirectUrl = new URL(consentRes.headers['location']);
      const code = redirectUrl.searchParams.get('code');
      assert.ok(code);

      // Exchange code for token
      const tokenRes = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:3000/test-client/callback.html',
          client_id: 'dx_client_test_app',
          code_verifier: verifier
        });

      assert.equal(tokenRes.status, 200);
      assert.ok(tokenRes.body.access_token);
      testAppToken = tokenRes.body.access_token;

      // Verify token works for UserInfo
      const userInfoRes = await request(app)
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${testAppToken}`);

      assert.equal(userInfoRes.status, 200);
      assert.equal(userInfoRes.body.sub, userObj.drexoraUserId);
    });

    test('User Charlie lists connected applications', async () => {
      const res = await request(app)
        .get('/api/account/connected-apps')
        .set('Cookie', userCookie);

      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.connectedApps));
      assert.ok(res.body.connectedApps.some(app => app.clientId === 'dx_client_test_app'));
    });

    test('User Charlie revokes access for Test App A', async () => {
      const res = await request(app)
        .delete('/api/account/connected-apps/dx_client_test_app')
        .set('Cookie', userCookie);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
    });

    test('Revoked access token immediately fails on UserInfo endpoint', async () => {
      const res = await request(app)
        .get('/oauth/userinfo')
        .set('Authorization', `Bearer ${testAppToken}`);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'invalid_token');
    });
  });

  describe('4. Product Registry, Product Access, and Entitlements Foundation', () => {
    test('GET /api/platform/products lists registered products', async () => {
      const res = await request(app).get('/api/platform/products');
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.products));
      assert.ok(res.body.products.some(p => p.productId === 'drexora_support'));
      assert.ok(res.body.products.some(p => p.productId === 'drexora_ai'));
    });

    test('GET /api/platform/my-access returns product summary for user', async () => {
      // Grant product access and entitlement via platform service
      await platformService.grantProductAccess(userObj.drexoraUserId, 'drexora_support', 'active');
      await platformService.setUserEntitlements(userObj.drexoraUserId, 'drexora_support', ['support.basic', 'support.ai']);
      await platformService.setUserSubscription(userObj.drexoraUserId, 'drexora_support', { planId: 'pro', durationDays: 30 });

      const res = await request(app)
        .get('/api/platform/my-access')
        .set('Cookie', userCookie);

      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.productAccess));
      assert.ok(Array.isArray(res.body.entitlements));
      assert.ok(Array.isArray(res.body.subscriptions));

      assert.equal(res.body.productAccess[0].productId, 'drexora_support');
      assert.deepEqual(res.body.entitlements[0].entitlements, ['support.basic', 'support.ai']);
      assert.equal(res.body.subscriptions[0].planId, 'pro');
    });
  });

  describe('5. Audit Service Sanitization', () => {
    test('Audit log metadata strips passwords, secrets, and raw tokens', async () => {
      const log = await auditService.logEvent({
        event: 'test.security.event',
        userId: userObj.drexoraUserId,
        metadata: {
          password: 'SecretPassword123!',
          clientSecret: 'dx_secret_123456789',
          accessToken: 'dx_at_999999999',
          safeKey: 'SafeMetadataValue'
        }
      });

      assert.equal(log.metadata.password, '[REDACTED]');
      assert.equal(log.metadata.clientSecret, '[REDACTED]');
      assert.equal(log.metadata.accessToken, '[REDACTED]');
      assert.equal(log.metadata.safeKey, 'SafeMetadataValue');
    });
  });

  describe('6. Account Deletion Workflow', () => {
    let deleteTargetCookie = '';
    let deleteTargetUser = null;

    before(async () => {
      // Create account to delete
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          fullName: 'User DeleteMe',
          email: 'deleteme@example.com',
          password: 'Password123!',
          confirmPassword: 'Password123!'
        });
      deleteTargetUser = { drexoraUserId: res.body.drexoraUserId };
      await userService.markEmailVerified(deleteTargetUser.drexoraUserId);

      const login = await request(app)
        .post('/api/auth/login')
        .send({ email: 'deleteme@example.com', password: 'Password123!' });
      deleteTargetCookie = login.headers['set-cookie'];
    });

    test('Account deletion with wrong password is rejected', async () => {
      const res = await request(app)
        .post('/api/account/delete')
        .set('Cookie', deleteTargetCookie)
        .send({ password: 'WrongPassword!' });

      assert.equal(res.status, 400);
      assert.ok(res.body.error.includes('Incorrect password'));
    });

    test('Account deletion with correct password succeeds and invalidates login', async () => {
      const res = await request(app)
        .post('/api/account/delete')
        .set('Cookie', deleteTargetCookie)
        .send({ password: 'Password123!' });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');

      // Attempt login with deleted account should fail
      const loginAttempt = await request(app)
        .post('/api/auth/login')
        .send({ email: 'deleteme@example.com', password: 'Password123!' });

      assert.equal(loginAttempt.status, 401);
    });
  });
});
