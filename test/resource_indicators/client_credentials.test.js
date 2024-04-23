import sinon from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

const route = '/token';

describe('grant_type=client_credentials w/ resourceIndicators', () => {
  before(bootstrap(import.meta.url, { config: 'client_credentials' }));

  it('provides a Bearer client credentials opaque token', function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.saved', spy);

    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:opaque',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.firstCall.args[0]).to.have.property('scope').and.eql('api:read');
        expect(spy.firstCall.args[0]).to.have.property('aud').and.eql('urn:wl:opaque');
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
        expect(response.body.scope).to.eql('api:read');
      });
  });

  it('provides a Bearer client credentials jwt token', function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.issued', spy);

    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:jwt',
      })
      .type('form')
      .expect(200)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.firstCall.args[0]).to.have.property('scope').and.eql('api:read');
        expect(spy.firstCall.args[0]).to.have.property('aud').and.eql('urn:wl:jwt');
      })
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
        expect(response.body.scope).to.eql('api:read');
      });
  });

  it('ignores unsupported scopes', function () {
    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
        resource: 'urn:wl',
      })
      .type('form')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.keys('access_token', 'expires_in', 'token_type', 'scope');
        expect(response.body.scope).to.eql('api:read');
      });
  });

  it('can reject resource indicator', function () {
    return this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:admin',
        resource: 'urn:bl',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_target',
        error_description: 'resource indicator is missing, or unknown',
      });
  });

  it('only supports a single resource indicator', function () {
    return this.agent.post(route)
      .auth('client', 'secret')
      .send('grant_type=client_credentials&scope=api:read&resource=urn:wl:opaque:default&resource=urn:wl:opaque:explicit')
      .type('form')
      .expect(400)
      .expect(/invalid_target/)
      .expect(/only a single resource indicator value is supported/);
  });

  it('validates each resource to be a valid URI individually', function () {
    return this.agent.post(route)
      .auth('client', 'secret')
      .send('grant_type=client_credentials&scope=api:read&resource=urn:wl:opaque:default&resource=invalid')
      .type('form')
      .expect(400)
      .expect(/invalid_target/)
      .expect(/resource indicator must be an absolute URI/);
  });

  it('checks the policy and adds the resource', async function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.saved', spy);
    this.provider.once('client_credentials.issued', spy);

    await this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:not:allowed',
      })
      .type('form')
      .expect(400)
      .expect({
        error: 'invalid_target',
        error_description: 'resource indicator is missing, or unknown',
      });

    await this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: 'urn:wl:opaque:explicit',
      })
      .type('form')
      .expect(200);

    expect(spy.calledOnce).to.be.true;
    const token = spy.args[0][0];
    expect(token.aud).to.equal('urn:wl:opaque:explicit');
    expect(token.scope).to.equal('api:read');
  });

  it('also ignores resource unrecognized scopes', async function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.saved', spy);
    this.provider.once('client_credentials.issued', spy);

    await this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read api:write unrecognized',
        resource: 'urn:wl:opaque:explicit',
      })
      .type('form')
      .expect(200);

    expect(spy.calledOnce).to.be.true;
    const token = spy.args[0][0];
    expect(token.aud).to.equal('urn:wl:opaque:explicit');
    expect(token.scope).to.equal('api:read api:write');
  });

  it('applies the default resource', async function () {
    const spy = sinon.spy();
    this.provider.once('client_credentials.saved', spy);
    this.provider.once('client_credentials.issued', spy);

    await this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .expect(200);

    expect(spy.calledOnce).to.be.true;
    const token = spy.args[0][0];
    expect(token.aud).to.equal('urn:wl:opaque:default');
  });

  it('populates ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'ClientCredentials');
    }, done));

    this.agent.post(route)
      .auth('client', 'secret')
      .send({
        grant_type: 'client_credentials',
        scope: 'api:read',
      })
      .type('form')
      .end(() => {});
  });
});
