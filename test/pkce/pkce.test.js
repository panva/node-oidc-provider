import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse as parseUrl } from 'node:url';


import bootstrap, { passInteractionChecks } from '../test_helper.js';

describe('PKCE RFC7636', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('authorization', () => {
    const fixture1 = Object.create(fixture);

    before(() => fixture1.login(), { timeout: 3000 });

    it('checks that codeChallenge is provided if codeChallengeMethod was', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: undefined,
        code_challenge_method: 'S256',
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('code_challenge must be provided with code_challenge_method'));
    });

    it('checks that codeChallenge is conform to its ABNF (too short)', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge_method: 'S256',
        code_challenge: 'f'.repeat(42),
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('code_challenge must be a string with a minimum length of 43 characters'));
    });

    it('checks that codeChallenge is conform to its ABNF (too long)', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge_method: 'S256',
        code_challenge: 'f'.repeat(129),
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('code_challenge must be a string with a maximum length of 128 characters'));
    });

    it('checks that codeChallenge is conform to its ABNF (charset)', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge_method: 'S256',
        code_challenge: `${'f'.repeat(42)}&`,
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('code_challenge contains invalid characters'));
    });

    it('validates the value of codeChallengeMethod if provided', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'bar',
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('not supported value of code_challenge_method'));
    });

    it('forces public clients using code flow to use pkce', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: undefined,
        code_challenge_method: undefined,
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('Authorization Server policy requires PKCE to be used for this request'));
    });

    it('forces public clients using hybrid flow to use pkce', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code id_token',
        scope: 'openid',
        code_challenge: undefined,
        code_challenge_method: undefined,
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('Authorization Server policy requires PKCE to be used for this request'));
    });

    passInteractionChecks(fixture1, 'native_client_prompt', () => {
      const fixture2 = Object.create(fixture1);

      it('is not in effect for implicit flows', { timeout: 3000 }, () => {
        const auth = new fixture2.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
        });

        return fixture2.agent.get('/auth')
          .query(auth)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']));
      });
    });

    it('stores codeChallenge and codeChallengeMethod in the code', { timeout: 3000 }, () => {
      const auth = new fixture1.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      });

      return fixture1.agent.get('/auth')
        .query(auth)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = fixture1.getTokenJti(code);
          const stored = fixture1.TestAdapter.for('AuthorizationCode').syncFind(jti);

          ((actual) => { assert.ok('codeChallengeMethod' in Object(actual)); assert.equal(actual.codeChallengeMethod, 'S256'); })(stored);
          ((actual) => { assert.ok('codeChallenge' in Object(actual)); assert.equal(actual.codeChallenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'); })(stored);
        });
    });
  });

  describe('token grant_type=authorization_code', () => {
    const fixture3 = Object.create(fixture);

    before(() => fixture3.login(), { timeout: 3000 });

    it('rejects code_verifier when the authorization code has no codeChallenge', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();
      const request = {
        client_id: 'client',
        code,
        grant_type: 'authorization_code',
        redirect_uri: 'com.example.myapp:/localhost/cb',
      };

      await fixture3.agent.post('/token')
        .type('form')
        .send({
          ...request,
          code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        })
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'code_verifier must not be provided without a code_challenge',
        });

      return fixture3.agent.post('/token')
        .type('form')
        .send(request)
        .expect(200);
    });

    it('passes with S256 values', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        })
        .expect(200);
    });

    it('checks presence of code_verifier param if code has codeChallenge', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();
      let emitted;
      fixture3.provider.once('grant.error', (_ctx, err) => {
        emitted = err;
      });

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          assert.ok(!('error_detail' in Object(response.body)));
          assert.ok(!('cause' in Object(response.body)));
          assert.ok(emitted.cause instanceof Error);
          ((actual) => { assert.equal(actual, emitted.cause.message); assert.equal(actual, 'code_verifier must be provided'); })(emitted.error_detail);
        });
    });

    it('checks value of code_verifier when method = S256', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();
      let emitted;
      fixture3.provider.once('grant.error', (_ctx, err) => {
        emitted = err;
      });

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'invalidE9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          assert.ok(emitted.cause instanceof Error);
          ((actual) => { assert.equal(actual, emitted.cause.message); assert.equal(actual, 'code_verifier does not match code_challenge'); })(emitted.error_detail);
        });
    });

    it('checks that code_verifier is conform to its ABNF (too short)', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'f'.repeat(42),
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'code_verifier must be a string with a minimum length of 43 characters'); })(response.body);
        });
    });

    it('checks that code_verifier is conform to its ABNF (too long)', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'f'.repeat(129),
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'code_verifier must be a string with a maximum length of 128 characters'); })(response.body);
        });
    });

    it('checks that code_verifier is conform to its ABNF (charset)', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: `${'f'.repeat(42)}&`,
        })
        .expect(400)
        .expect((response) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(response.body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'code_verifier contains invalid characters'); })(response.body);
        });
    });

    it('passes if S256 is used', { timeout: 3000 }, async () => {
      const authCode = new fixture3.provider.AuthorizationCode({
        accountId: fixture3.loggedInAccountId,
        grantId: fixture3.getGrantId(),
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return fixture3.agent.post('/token')
        .type('form')
        .send({
          client_id: 'client',
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        })
        .expect(200);
    });
  });
});
