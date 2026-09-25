const test = require('node:test');
const assert = require('node:assert/strict');
const supertest = require('supertest');

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test_secret_key';
process.env.APP_URL = 'http://localhost:3000';

const app = require('../src/server');
const db = require('../src/db/firebase');
const tokenService = require('../src/services/token.service');

function request() {
  return supertest(app);
}

test('Drexora Account Comprehensive Test Suite', async (t) => {
  let verificationCode = '';
  let rawPasswordResetToken = '';
  let sessionCookie = '';
  let secondSessionCookie = '';
  let userDrexoraId = '';

  const testUser = {
    fullName: 'Jane Doe',
    email: 'Jane.Doe@Example.com',
    password: 'Password123!',
    confirmPassword: 'Password123!'
  };

  await t.test('1. Health Check Endpoint', async () => {
    const res = await request().get('/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
  });

  await t.test('2. Registration Validation & Handling', async () => {
    // Missing fields
    const res1 = await request().post('/api/auth/register').send({});
    assert.equal(res1.status, 400);

    // Password mismatch
    const res2 = await request().post('/api/auth/register').send({
      fullName: 'Jane Doe',
      email: 'jane@example.com',
      password: 'Password123!',
      confirmPassword: 'DifferentPassword!'
    });
    assert.equal(res2.status, 400);

    // Weak password
    const res3 = await request().post('/api/auth/register').send({
      fullName: 'Jane Doe',
      email: 'jane@example.com',
      password: 'weak',
      confirmPassword: 'weak'
    });
    assert.equal(res3.status, 400);

    // Valid registration
    const res4 = await request().post('/api/auth/register').send(testUser);
    assert.equal(res4.status, 201);
    assert.ok(res4.body.drexoraUserId.startsWith('dx_'));
    assert.equal(res4.body.email, 'jane.doe@example.com');
    userDrexoraId = res4.body.drexoraUserId;

    // Duplicate registration attempt
    const res5 = await request().post('/api/auth/register').send(testUser);
    assert.equal(res5.status, 409);
  });

  await t.test('3. Login before verification should be blocked', async () => {
    const res = await request().post('/api/auth/login').send({
      email: testUser.email,
      password: testUser.password
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'EMAIL_UNVERIFIED');
  });

  await t.test('4. 8-Digit Code Email Verification Flow', async () => {
    // Generate known 8-digit verification code directly
    const tokenRes = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: userDrexoraId, email: 'jane.doe@example.com' },
      24 * 60 * 60 * 1000,
      true
    );
    verificationCode = tokenRes.rawToken;
    assert.equal(verificationCode.length, 8);

    // Verify with invalid code
    const res1 = await request().post('/api/auth/verify-email').send({ code: '00000000' });
    assert.equal(res1.status, 400);

    // Verify with valid 8-digit code
    const res2 = await request().post('/api/auth/verify-email').send({ code: verificationCode });
    assert.equal(res2.status, 200);

    // Verify account state
    const user = await db.get(`users/${userDrexoraId}`);
    assert.equal(user.emailVerified, true);
    assert.equal(user.accountStatus, 'active');

    // Attempt reuse of code
    const res3 = await request().post('/api/auth/verify-email').send({ code: verificationCode });
    assert.equal(res3.status, 400);
  });

  await t.test('5. Login & Multi-Device Session Creation', async () => {
    // Wrong password
    const res1 = await request().post('/api/auth/login').send({
      email: testUser.email,
      password: 'WrongPassword123!'
    });
    assert.equal(res1.status, 401);

    // Device 1 Login (Laptop)
    const res2 = await request()
      .post('/api/auth/login')
      .set('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Laptop')
      .send({
        email: testUser.email,
        password: testUser.password
      });

    assert.equal(res2.status, 200);
    assert.ok(res2.body.user);
    assert.equal(res2.body.user.drexoraUserId, userDrexoraId);

    const cookies1 = res2.headers['set-cookie'];
    assert.ok(cookies1 && cookies1.length > 0);
    sessionCookie = cookies1[0].split(';')[0];

    // Device 2 Login (Phone)
    const res3 = await request()
      .post('/api/auth/login')
      .set('User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) Phone')
      .send({
        email: testUser.email,
        password: testUser.password
      });

    assert.equal(res3.status, 200);
    const cookies2 = res3.headers['set-cookie'];
    secondSessionCookie = cookies2[0].split(';')[0];
  });

  await t.test('6. Session Inspection & Revocation', async () => {
    // Profile access
    const profileRes = await request()
      .get('/api/account/profile')
      .set('Cookie', sessionCookie);
    assert.equal(profileRes.status, 200);
    assert.equal(profileRes.body.profile.drexoraUserId, userDrexoraId);

    // Sessions listing
    const sessionsRes = await request()
      .get('/api/account/sessions')
      .set('Cookie', sessionCookie);
    assert.equal(sessionsRes.status, 200);
    assert.equal(sessionsRes.body.sessions.length, 2);

    // Revoke all other sessions
    const revokeRes = await request()
      .post('/api/account/sessions/revoke-others')
      .set('Cookie', sessionCookie);
    assert.equal(revokeRes.status, 200);

    // Device 2 access should now be revoked (401)
    const dev2Check = await request()
      .get('/api/account/profile')
      .set('Cookie', secondSessionCookie);
    assert.equal(dev2Check.status, 401);
  });

  await t.test('7. Password Change Flow', async () => {
    // Incorrect current password
    const res1 = await request()
      .post('/api/auth/change-password')
      .set('Cookie', sessionCookie)
      .send({
        currentPassword: 'WrongPassword!',
        newPassword: 'NewPassword123!',
        confirmNewPassword: 'NewPassword123!'
      });
    assert.equal(res1.status, 400);

    // Successful change
    const res2 = await request()
      .post('/api/auth/change-password')
      .set('Cookie', sessionCookie)
      .send({
        currentPassword: testUser.password,
        newPassword: 'NewPassword123!',
        confirmNewPassword: 'NewPassword123!'
      });
    assert.equal(res2.status, 200);

    // Login with new password
    const loginNew = await request()
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: 'NewPassword123!'
      });
    assert.equal(loginNew.status, 200);

    // Update active cookie
    const cookies = loginNew.headers['set-cookie'];
    sessionCookie = cookies[0].split(';')[0];
  });

  await t.test('8. Password Reset Request & Confirmation', async () => {
    // Request reset
    const res1 = await request()
      .post('/api/auth/forgot-password')
      .send({ email: testUser.email });
    assert.equal(res1.status, 200);

    // Generate known reset token
    const tokenRes = await tokenService.createToken(
      'passwordResetTokens',
      { drexoraUserId: userDrexoraId, email: 'jane.doe@example.com' },
      60 * 60 * 1000
    );
    rawPasswordResetToken = tokenRes.rawToken;

    // Reset password
    const res2 = await request()
      .post('/api/auth/reset-password')
      .send({
        token: rawPasswordResetToken,
        newPassword: 'ResetPassword123!',
        confirmNewPassword: 'ResetPassword123!'
      });
    assert.equal(res2.status, 200);

    // Login with reset password
    const loginReset = await request()
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: 'ResetPassword123!'
      });
    assert.equal(loginReset.status, 200);

    const cookies = loginReset.headers['set-cookie'];
    sessionCookie = cookies[0].split(';')[0];
  });

  await t.test('9. Account Status Enforcement (Suspended/Disabled)', async () => {
    // Suspend user
    await db.update(`users/${userDrexoraId}`, { accountStatus: 'suspended' });

    // Protected endpoint attempt
    const res1 = await request()
      .get('/api/account/profile')
      .set('Cookie', sessionCookie);
    assert.equal(res1.status, 403);

    // Login attempt
    const res2 = await request()
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: 'ResetPassword123!'
      });
    assert.equal(res2.status, 403);

    // Restore active status
    await db.update(`users/${userDrexoraId}`, { accountStatus: 'active' });
  });

  await t.test('10. Logout Endpoint', async () => {
    const res = await request()
      .post('/api/auth/logout')
      .set('Cookie', sessionCookie);
    assert.equal(res.status, 200);

    // Subsequent call returns 401
    const checkRes = await request()
      .get('/api/account/profile')
      .set('Cookie', sessionCookie);
    assert.equal(checkRes.status, 401);
  });
});
