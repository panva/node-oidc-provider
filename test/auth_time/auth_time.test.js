const url = require('url');

const sinon = require('sinon');
const { JWT: { decode } } = require('jose');
const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('responds with a id_token containing auth_time', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });

  const response_type = 'id_token';
  const scope = 'openid';

  it('when max_age was present in the request', async function () {
    const auth = new this.AuthorizationRequest({
      response_type,
      scope,
      max_age: 999,
    });

    let id_token;

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    expect(decode(id_token)).to.have.property('auth_time');
  });

  context('special cases', () => {
    const sandbox = sinon.createSandbox();

    before(function () {
      sandbox.stub(this.provider.OIDCContext.prototype, 'promptPending').returns(false);
    });

    after(sandbox.restore);

    it('when prompt=login was requested', async function () {
      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
        prompt: 'login',
      });

      let id_token;

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          ({ query: { id_token } } = url.parse(response.headers.location, true));
        });

      expect(decode(id_token)).to.have.property('auth_time');
    });

    it('when max_age=0 was requested', async function () {
      const auth = new this.AuthorizationRequest({
        response_type,
        scope,
        max_age: 0,
      });

      let id_token;

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect((response) => {
          ({ query: { id_token } } = url.parse(response.headers.location, true));
        });

      expect(decode(id_token)).to.have.property('auth_time');
    });
  });

  it('when client has require_auth_time', async function () {
    const auth = new this.AuthorizationRequest({
      response_type,
      scope,
      client_id: 'client-with-require_auth_time',
    });

    let id_token;

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    expect(decode(id_token)).to.have.property('auth_time');
  });

  it('when client has default_max_age', async function () {
    const auth = new this.AuthorizationRequest({
      response_type,
      scope,
      client_id: 'client-with-default_max_age',
    });

    let id_token;

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect((response) => {
        ({ query: { id_token } } = url.parse(response.headers.location, true));
      });

    expect(decode(id_token)).to.have.property('auth_time');
  });
});
