const querystring = require('querystring');

const { expect } = require('chai');

const bootstrap = require('../test_helper');

function register(provider, grantType, params, options) {
  provider.registerGrantType(grantType, (ctx) => {
    ctx.body = { winner: ctx.oidc.params.name };
  }, params, options);
}

describe('custom token endpoint grant types', () => {
  before(bootstrap(__dirname));

  before('allows for grant types to be added', function () {
    register(this.provider, 'lotto', 'name');
    expect(i(this.provider).configuration('grantTypes').has('lotto')).to.be.true;
  });

  it('does not need to be passed extra parameters', function () {
    register(this.provider, 'lotto-2');
    expect(i(this.provider).configuration('grantTypes').has('lotto-2')).to.be.true;
  });

  it('can be passed null or a string', function () {
    register(this.provider, 'lotto-3', null);
    register(this.provider, 'lotto-4', 'name');

    expect(i(this.provider).configuration('grantTypes').has('lotto-3')).to.be.true;
    expect(i(this.provider).configuration('grantTypes').has('lotto-4')).to.be.true;
  });

  describe('when added', () => {
    before(async function () {
      const client = await this.provider.Client.find('client');
      client.grantTypes.push('lotto');
    });

    describe('rejectDupes behavior', () => {
      const data = `${querystring.stringify({ grant_type: 'lotto', name: 'John Doe' })}&name=FooBar`;
      it('by default reject dupes', function () {
        return this.agent.post('/token')
          .auth('client', 'secret')
          .send(data)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'name' parameter must not be provided twice",
          });
      });

      // see OAuth 2.0 Token Exchange - audience and resource
      it('can be exempt params from being dupe-checked', function () {
        register(this.provider, 'lotto', 'name', ['name']);
        return this.agent.post('/token')
          .auth('client', 'secret')
          .send(data)
          .type('form')
          .expect(200)
          .expect({ winner: ['John Doe', 'FooBar'] });
      });

      it('can be exempt params from being dupe-checked but still checks other params', function () {
        register(this.provider, 'lotto', new Set(['name', 'foo']), new Set(['name']));
        return this.agent.post('/token')
          .auth('client', 'secret')
          .send(`${data}&foo=bar&foo=bar`)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'foo' parameter must not be provided twice",
          });
      });

      it('can be exempt params from being dupe-checked (except for grant_type)', function () {
        register(this.provider, 'lotto', 'name', 'name');
        return this.agent.post('/token')
          .auth('client', 'secret')
          .send(`${data}&grant_type=lotto`)
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_request',
            error_description: "'grant_type' parameter must not be provided twice",
          });
      });
    });

    it('clients can start using it', function () {
      return this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'lotto', name: 'John Doe' })
        .type('form')
        .expect(200)
        .expect({ winner: 'John Doe' });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client');
      }, done));

      this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'lotto', name: 'John Doe' })
        .type('form')
        .end(() => {});
    });
  });
});
