const test = require('node:test');
const assert = require('node:assert/strict');
const supertest = require('supertest');
const crypto = require('crypto');

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test_secret_key';
process.env.APP_URL = 'http://localhost:3000';

const app = require('../src/server');
const db = require('../src/db/firebase');
const tokenService = require('../src/services/token.service');
const oauthService = require('../src/services/oauth.service');

function request() {
  return supertest(app);
}

function generatePkcePair() {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

test('Drexora Account — Profile Completion, Phone Verification & Scope Data Sharing Test Suite', async (t) => {
  let userAId = '';
  let userACookie = '';
  let userAToken = '';
  let userBId = '';
  let userBToken = '';
  let clientAId = 'dx_client_test_app';

  const userA = {
    fullName: 'Alice Smith',
    email: 'profile.alice.sso@example.com',
    password: 'Password123!',
    confirmPassword: 'Password123!'
  };

  const userB = {
    fullName: 'Bob Johnson',
    email: 'profile.bob.sso@example.com',
    password: 'Password123!',
    confirmPassword: 'Password123!'
  };

  // Seed test client
  await oauthService.seedTestClient();

  await t.test('1. Test 1 — New Account Registration & Email Verification', async () => {
    const regRes = await request().post('/api/auth/register').send(userA);
    assert.equal(regRes.status, 201);
    assert.ok(regRes.body.drexoraUserId);
    userAId = regRes.body.drexoraUserId;

    // Verify email with 8-digit code
    const tokenRes = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: userAId, email: userA.email },
      24 * 60 * 60 * 1000,
      true
    );
    const code = tokenRes.rawToken;

    const verifyRes = await request().post('/api/auth/verify-email').send({ code });
    assert.equal(verifyRes.status, 200);

    // Login user A
    const loginRes = await request().post('/api/auth/login').send({
      email: userA.email,
      password: userA.password
    });

    assert.equal(loginRes.status, 200);
    assert.equal(loginRes.body.user.profileCompleted, false);
    assert.ok(loginRes.body.token);

    userAToken = loginRes.body.token;
    const cookies = loginRes.headers['set-cookie'];
    assert.ok(cookies && cookies.length > 0);
    userACookie = cookies[0].split(';')[0];
  });

  await t.test('2. Test 3 — Incomplete Profile Status Identification', async () => {
    const profileRes = await request()
      .get('/api/account/profile')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(profileRes.status, 200);
    const profile = profileRes.body.profile;
    assert.equal(profile.profileCompleted, false);
    assert.ok(profile.profileStatus.missingRequiredFields.includes('phone'));
    assert.ok(profile.profileStatus.missingRequiredFields.includes('country'));
    assert.equal(profile.phoneVerified, false);
  });

  await t.test('3. Test 4 — Profile Completion & Phone Verification Workflow', async () => {
    // Fill required profile fields
    const patchRes = await request()
      .patch('/api/account/profile')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        firstName: 'Alice',
        lastName: 'Smith',
        displayName: 'Alice Smith',
        phone: '+14155552671',
        country: 'United States',
        state: 'California',
        city: 'San Francisco',
        address: '500 Howard Street',
        postalCode: '94105'
      });

    assert.equal(patchRes.status, 200);
    assert.equal(patchRes.body.profile.profileCompleted, true);
    assert.equal(patchRes.body.profile.phoneVerified, false);

    // Request phone verification code
    const sendCodeRes = await request()
      .post('/api/account/phone/send-verification')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ phone: '+14155552671' });

    assert.equal(sendCodeRes.status, 200);
    assert.equal(sendCodeRes.body.success, true);
    assert.ok(sendCodeRes.body.debugCode);

    const phoneCode = sendCodeRes.body.debugCode;

    // Confirm phone verification code
    const confirmRes = await request()
      .post('/api/account/phone/verify')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ code: phoneCode });

    assert.equal(confirmRes.status, 200);
    assert.equal(confirmRes.body.phoneVerified, true);

    // Re-check public profile
    const checkRes = await request()
      .get('/api/account/profile')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(checkRes.body.profile.phoneVerified, true);
    assert.equal(checkRes.body.profile.profileCompleted, true);

    // Test phone change resets phoneVerified to false
    const changePhoneRes = await request()
      .patch('/api/account/profile')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ phone: '+14155559999' });

    assert.equal(changePhoneRes.status, 200);
    assert.equal(changePhoneRes.body.profile.phoneVerified, false);

    // Re-verify back to +14155552671 for subsequent SSO tests
    const restorePhoneRes = await request()
      .post('/api/account/phone/send-verification')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ phone: '+14155552671' });

    const restoreVerifyRes = await request()
      .post('/api/account/phone/verify')
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ code: restorePhoneRes.body.debugCode });

    assert.equal(restoreVerifyRes.status, 200);
    assert.equal(restoreVerifyRes.body.phoneVerified, true);
  });

  await t.test('4. Test 2 — Complete Profile Existing User Login', async () => {
    const loginRes = await request().post('/api/auth/login').send({
      email: userA.email,
      password: userA.password
    });

    assert.equal(loginRes.status, 200);
    assert.equal(loginRes.body.user.profileCompleted, true);
    userAToken = loginRes.body.token;
    userACookie = loginRes.headers['set-cookie'][0].split(';')[0];
  });

  await t.test('5. Test 5 — Continue with Drexora (openid profile email)', async () => {
    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email&state=state123&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=approved`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(authRes.status, 302);
    const redirectUrl = new URL(authRes.headers.location);
    const code = redirectUrl.searchParams.get('code');
    assert.ok(code);

    const tokenRes = await request()
      .post('/oauth/token')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000/test-client/callback.html',
        client_id: clientAId,
        code_verifier: pkce.verifier
      });

    assert.equal(tokenRes.status, 200);
    const accessToken = tokenRes.body.access_token;
    assert.ok(accessToken);

    const userInfoRes = await request()
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${accessToken}`);

    assert.equal(userInfoRes.status, 200);
    assert.equal(userInfoRes.body.sub, userAId);
    assert.equal(userInfoRes.body.name, 'Alice Smith');
    assert.equal(userInfoRes.body.email, 'profile.alice.sso@example.com');
    assert.equal(userInfoRes.body.email_verified, true);

    assert.equal(userInfoRes.body.phone_number, undefined);
    assert.equal(userInfoRes.body.address, undefined);
  });

  await t.test('6. Test 6 — Phone Scope Data Sharing (openid profile email phone)', async () => {
    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email%20phone&state=state456&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=approved`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(authRes.status, 302);
    const redirectUrl = new URL(authRes.headers.location);
    const code = redirectUrl.searchParams.get('code');

    const tokenRes = await request()
      .post('/oauth/token')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000/test-client/callback.html',
        client_id: clientAId,
        code_verifier: pkce.verifier
      });

    assert.equal(tokenRes.status, 200);
    const accessToken = tokenRes.body.access_token;

    const userInfoRes = await request()
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${accessToken}`);

    assert.equal(userInfoRes.status, 200);
    assert.equal(userInfoRes.body.phone_number, '+14155552671');
    assert.equal(userInfoRes.body.phone_number_verified, true);
    assert.equal(userInfoRes.body.address, undefined);
  });

  await t.test('7. Test 7 — Address Scope Data Sharing (openid profile email address)', async () => {
    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email%20address&state=state789&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=approved`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(authRes.status, 302);
    const redirectUrl = new URL(authRes.headers.location);
    const code = redirectUrl.searchParams.get('code');

    const tokenRes = await request()
      .post('/oauth/token')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000/test-client/callback.html',
        client_id: clientAId,
        code_verifier: pkce.verifier
      });

    assert.equal(tokenRes.status, 200);
    const accessToken = tokenRes.body.access_token;

    const userInfoRes = await request()
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${accessToken}`);

    assert.equal(userInfoRes.status, 200);
    assert.ok(userInfoRes.body.address);
    assert.equal(userInfoRes.body.address.street_address, '500 Howard Street');
    assert.equal(userInfoRes.body.address.locality, 'San Francisco');
    assert.equal(userInfoRes.body.address.region, 'California');
    assert.equal(userInfoRes.body.address.postal_code, '94105');
    assert.equal(userInfoRes.body.address.country, 'United States');
  });

  await t.test('8. Test 8 — Consent Denial Handling', async () => {
    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email&state=deniedState&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=denied`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(authRes.status, 302);
    const redirectUrl = new URL(authRes.headers.location);
    assert.equal(redirectUrl.searchParams.get('error'), 'access_denied');
  });

  await t.test('9. Test 9 — Revoke Application Access', async () => {
    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email&state=revokeState&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=approved`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    const code = new URL(authRes.headers.location).searchParams.get('code');

    const tokenRes = await request()
      .post('/oauth/token')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000/test-client/callback.html',
        client_id: clientAId,
        code_verifier: pkce.verifier
      });

    const accessToken = tokenRes.body.access_token;

    const preCheck = await request().get('/oauth/userinfo').set('Authorization', `Bearer ${accessToken}`);
    assert.equal(preCheck.status, 200);

    const revokeRes = await request()
      .delete(`/api/account/connected-apps/${clientAId}`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.equal(revokeRes.status, 200);

    const postCheck = await request().get('/oauth/userinfo').set('Authorization', `Bearer ${accessToken}`);
    assert.equal(postCheck.status, 401);
  });

  await t.test('10. Test 10 — Security & Token-Based Identification', async () => {
    const regResB = await request().post('/api/auth/register').send(userB);
    userBId = regResB.body.drexoraUserId;

    const tokenResB = await tokenService.createToken(
      'verificationTokens',
      { drexoraUserId: userBId, email: userB.email },
      24 * 60 * 60 * 1000,
      true
    );
    await request().post('/api/auth/verify-email').send({ code: tokenResB.rawToken });

    const loginB = await request().post('/api/auth/login').send({ email: userB.email, password: userB.password });
    userBToken = loginB.body.token;

    const pkce = generatePkcePair();

    const authRes = await request()
      .get(`/oauth/authorize?client_id=${clientAId}&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ftest-client%2Fcallback.html&response_type=code&scope=openid%20profile%20email&state=secState&code_challenge=${pkce.challenge}&code_challenge_method=S256&consent=approved`)
      .set('Cookie', userACookie)
      .set('Authorization', `Bearer ${userAToken}`);

    const code = new URL(authRes.headers.location).searchParams.get('code');
    const tokenRes = await request().post('/oauth/token').send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'http://localhost:3000/test-client/callback.html',
      client_id: clientAId,
      code_verifier: pkce.verifier
    });

    const userATokenForApp = tokenRes.body.access_token;

    const secUserInfo = await request()
      .get(`/oauth/userinfo?userId=${userBId}`)
      .set('Authorization', `Bearer ${userATokenForApp}`);

    assert.equal(secUserInfo.status, 200);
    assert.equal(secUserInfo.body.sub, userAId);
    assert.notEqual(secUserInfo.body.sub, userBId);
  });
});
