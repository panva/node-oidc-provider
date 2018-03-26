const base64url = require('base64url');
const bootstrap = require('../test_helper');
const { parse: parseUrl } = require('url');
const { expect } = require('chai');

describe('PKCE RFC7636', () => {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, TestAdapter

  describe('authorization', () => {
    before(function () { return this.login(); });

    it('stores codeChallenge and codeChallengeMethod in the code', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: 'foobar',
        code_challenge_method: 'plain',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = code.substring(0, 48);
          const stored = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
          const payload = JSON.parse(base64url.decode(stored.payload));

          expect(payload).to.have.property('codeChallengeMethod', 'plain');
          expect(payload).to.have.property('codeChallenge', 'foobar');
        });
    });

    it('defaults the codeChallengeMethod if not provided', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: 'foobar',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect((response) => {
          const { query: { code } } = parseUrl(response.headers.location, true);
          const jti = code.substring(0, 48);
          const stored = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
          const payload = JSON.parse(base64url.decode(stored.payload));

          expect(payload).to.have.property('codeChallengeMethod', 'plain');
          expect(payload).to.have.property('codeChallenge', 'foobar');
        });
    });

    it('checks that codeChallenge is provided if codeChallengeMethod was', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge_method: 'S256',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('code_challenge must be provided with code_challenge_method'));
    });

    it('validates the value of codeChallengeMethod if provided', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        code_challenge: 'foobar',
        code_challenge_method: 'bar',
      });

      return this.agent.get('/auth')
        .query(auth)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('not supported value of code_challenge_method'));
    });

    describe('forcedForNative flag', () => {
      before(function () {
        i(this.provider).configuration('features.pkce').forcedForNative = true;
      });

      after(function () {
        i(this.provider).configuration('features.pkce').forcedForNative = false;
      });

      it('forces native clients using code flow to use pkce', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('PKCE must be provided for native clients'));
      });

      it('forces native clients using hybrid flow to use pkce', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code id_token',
          scope: 'openid',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('PKCE must be provided for native clients'));
      });

      it('is not in effect for implicit flows', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']));
      });
    });

    describe('only S256 is supported', () => {
      before(function () {
        i(this.provider).configuration('features.pkce').supportedMethods = ['S256'];
      });

      after(function () {
        i(this.provider).configuration('features.pkce').supportedMethods = ['plain', 'S256'];
      });

      it('fails when client does not provide challenge method', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'foobar',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('not supported value of code_challenge_method'));
      });

      it('fails when client uses plain method', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'foobar',
          code_challenge_method: 'plain',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('not supported value of code_challenge_method'));
      });

      it('stores codeChallenge and codeChallengeMethod in the code', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          code_challenge_method: 'S256',
        });

        return this.agent.get('/auth')
          .query(auth)
          .expect((response) => {
            const { query: { code } } = parseUrl(response.headers.location, true);
            const jti = code.substring(0, 48);
            const stored = this.TestAdapter.for('AuthorizationCode').syncFind(jti);
            const payload = JSON.parse(base64url.decode(stored.payload));

            expect(payload).to.have.property('codeChallengeMethod', 'S256');
            expect(payload).to.have.property('codeChallenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
          });
      });
    });
  });

  describe('token grant_type=authorization_code', () => {
    it('passes with plain values', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'plainFoobar',
        codeChallengeMethod: 'plain',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'plainFoobar',
        })
        .expect(200);
    });

    it('passes with S256 values', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        })
        .expect(200);
    });

    it('checks presence of code_verifier param if code has codeChallenge', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'plainFoobar',
        codeChallengeMethod: 'plain',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
        })
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('checks value of code_verifier when method = plain', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'plainFoobar',
        codeChallengeMethod: 'plain',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'plainFoobars',
        })
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    it('checks value of code_verifier when method = S256', async function () {
      const authCode = new this.provider.AuthorizationCode({
        accountId: 'sub',
        scope: 'openid',
        clientId: 'client',
        codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        codeChallengeMethod: 'S256',
        redirectUri: 'com.example.myapp:/localhost/cb',
      });
      const code = await authCode.save();

      return this.agent.post('/token')
        .auth('client', 'secret')
        .type('form')
        .send({
          code,
          grant_type: 'authorization_code',
          redirect_uri: 'com.example.myapp:/localhost/cb',
          code_verifier: 'invalidE9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        })
        .expect(400)
        .expect((response) => {
          expect(response.body).to.have.property('error', 'invalid_grant');
        });
    });

    describe('only S256 is supported', () => {
      before(function () {
        i(this.provider).configuration('features.pkce').supportedMethods = ['S256'];
      });

      after(function () {
        i(this.provider).configuration('features.pkce').supportedMethods = ['plain', 'S256'];
      });

      it('passes if S256 is used', async function () {
        const authCode = new this.provider.AuthorizationCode({
          accountId: 'sub',
          scope: 'openid',
          clientId: 'client',
          codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          codeChallengeMethod: 'S256',
          redirectUri: 'com.example.myapp:/localhost/cb',
        });
        const code = await authCode.save();

        return this.agent.post('/token')
          .auth('client', 'secret')
          .type('form')
          .send({
            code,
            grant_type: 'authorization_code',
            redirect_uri: 'com.example.myapp:/localhost/cb',
            code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
          })
          .expect(200);
      });
    });
  });
});
