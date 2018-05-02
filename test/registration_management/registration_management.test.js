const { omit } = require('lodash');
const bootstrap = require('../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');
const Provider = require('../../lib');

describe('OAuth 2.0 Dynamic Client Registration Management Protocol', () => {
  before(bootstrap(__dirname)); // provider, agent

  // setup does not have the provider;

  function setup(meta) {
    const props = Object.assign({
      redirect_uris: ['https://client.example.com/cb'],
    }, meta);

    return this.agent.post('/reg').send(props).expect(201)
      .then(res => res.body);
  }

  describe('feature flag', () => {
    it('checks registration is also enabled', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            registrationManagement: true,
          },
        });
      }).to.throw('registrationManagement is only available in conjuction with registration');
    });
  });

  describe('Client Update Request', () => {
    const NOGO = ['registration_access_token', 'registration_client_uri', 'client_secret_expires_at', 'client_id_issued_at'];
    function updateProperties(client, props) {
      return Object.assign(omit(client, NOGO), props);
    }

    it('responds w/ 200 JSON and nocache headers', async function () {
      const client = await setup.call(this, {});
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
        }))
        .expect(200)
        .expect('content-type', /application\/json/)
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store')
        .expect((res) => {
          expect(res.body).to.have.property('registration_access_token', client.registration_access_token);
          expect(res.body).to.have.property('registration_client_uri', client.registration_client_uri);
          expect(res.body).to.have.property('client_secret_expires_at', client.client_secret_expires_at);
          expect(res.body).to.have.property('client_id_issued_at', client.client_id_issued_at);
          expect(res.body.redirect_uris).to.eql(['https://client.example.com/foobar/cb']);
        });
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RegistrationAccessToken');
      }, done, ctx => ctx.method === 'PUT'));

      (async () => {
        const client = await setup.call(this, {});
        await this.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client));
      })().catch(done);
    });

    it('allows for properties to be deleted', async function () {
      const client = await setup.call(this, { userinfo_signed_response_alg: 'RS256' });
      // removing userinfo_signed_response_alg and having it defaulted
      // console.log(client);
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          userinfo_signed_response_alg: null,
        }))
        .expect(200)
        .expect((res) => {
          expect(res.body).not.to.have.property('userinfo_signed_response_alg');
        });
    });

    it('must contain all previous properties', async function () {
      const client = await setup.call(this, { userinfo_signed_response_alg: 'RS256' });
      // removing userinfo_signed_response_alg and having it defaulted
      // console.log(client);
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          userinfo_signed_response_alg: undefined,
        }))
        .expect(400)
        .expect((res) => {
          expect(res.body).to.eql({
            error: 'invalid_request',
            error_description: 'userinfo_signed_response_alg must be provided',
          });
        });
    });

    it('provides a secret if suddently needed', async function () {
      const client = await setup.call(this, { token_endpoint_auth_method: 'none', response_types: ['id_token'], grant_types: ['implicit'] });
      // removing userinfo_signed_response_alg and having it defaulted
      // console.log(client);
      expect(client).not.to.have.property('client_secret');
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'client_secret_basic',
        }))
        .expect(200)
        .expect((res) => {
          expect(res.body).to.have.property('client_secret');
          expect(res.body).to.have.property('client_secret_expires_at');
        });
    });

    it('emits an event', async function () {
      const client = await setup.call(this, {});
      const spy = sinon.spy();
      this.provider.once('registration_update.success', spy);

      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client))
        .expect(200)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        });
    });

    it('must not contain registration_access_token', async function () {
      const client = await setup.call(this, {});
      // changing the redirect_uris;
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          registration_access_token: 'foobar',
        }))
        .expect(400)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'request MUST NOT include the "registration_access_token" field',
          });
        });
    });

    it('must not contain registration_client_uri', async function () {
      const client = await setup.call(this, {});
      // changing the redirect_uris;
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          registration_client_uri: 'foobar',
        }))
        .expect(400)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'request MUST NOT include the "registration_client_uri" field',
          });
        });
    });

    it('must not contain client_secret_expires_at', async function () {
      const client = await setup.call(this, {});
      // changing the redirect_uris;
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          client_secret_expires_at: 'foobar',
        }))
        .expect(400)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'request MUST NOT include the "client_secret_expires_at" field',
          });
        });
    });

    it('must not contain client_id_issued_at', async function () {
      const client = await setup.call(this, {});
      // changing the redirect_uris;
      return this.agent.put(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .send(updateProperties(client, {
          redirect_uris: ['https://client.example.com/foobar/cb'],
          client_id_issued_at: 'foobar',
        }))
        .expect(400)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'request MUST NOT include the "client_id_issued_at" field',
          });
        });
    });

    it('cannot update non-dynamic clients', async function () {
      const rat = new (this.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      const client = await this.provider.Client.find('client');
      return this.agent.put('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .send(updateProperties(client.metadata(), {
          redirect_uris: ['https://client.example.com/foobar/cb'],
        }))
        .expect(403)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'this client is not allowed to update its records',
          });
        });
    });

    describe('rotateRegistrationAccessToken', () => {
      before(function () {
        const conf = i(this.provider).configuration();
        conf.features.registrationManagement = { rotateRegistrationAccessToken: true };
      });

      after(function () {
        const conf = i(this.provider).configuration();
        conf.features.registrationManagement = true;
      });

      it('destroys the old RegistrationAccessToken', async function () {
        const client = await setup.call(this, {});
        const spy = sinon.spy();
        this.provider.once('token.revoked', spy);

        return this.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client))
          .expect(200)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          });
      });

      it('populates ctx.oidc.entities with RotatedRegistrationAccessToken too', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.contain.keys('RotatedRegistrationAccessToken', 'RegistrationAccessToken');
          expect(ctx.oidc.entities.RotatedRegistrationAccessToken)
            .not.to.eql(ctx.oidc.entities.RegistrationAccessToken);
        }, done, ctx => ctx.method === 'PUT'));

        (async () => {
          const client = await setup.call(this, {});
          await this.agent.put(`/reg/${client.client_id}`)
            .auth(client.registration_access_token, { type: 'bearer' })
            .send(updateProperties(client));
        })().catch(done);
      });

      it('issues and returns new RegistrationAccessToken', async function () {
        const client = await setup.call(this, {});
        const spy = sinon.spy();
        this.provider.once('token.issued', spy);

        return this.agent.put(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' })
          .send(updateProperties(client))
          .expect(200)
          .expect((response) => {
            expect(spy.calledOnce).to.be.true;
            const args = spy.firstCall.args[0];
            expect(args.clientId).to.equal(client.client_id);
            expect(response.body.registration_access_token.substring(0, 48)).to.equal(args.jti);
          });
      });
    });
  });

  describe('Client Delete Request', () => {
    it('responds w/ empty 204 and nocache headers', async function () {
      const client = await setup.call(this, {});
      return this.agent.del(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .expect('pragma', 'no-cache')
        .expect('cache-control', 'no-cache, no-store')
        .expect('') // empty body
        .expect(204);
    });

    it('populates ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.have.keys('Client', 'RegistrationAccessToken');
      }, done, ctx => ctx.method === 'DELETE'));

      (async () => {
        const client = await setup.call(this, {});
        await this.agent.del(`/reg/${client.client_id}`)
          .auth(client.registration_access_token, { type: 'bearer' });
      })().catch(done);
    });

    it('emits an event', async function () {
      const client = await setup.call(this, {});
      const spy = sinon.spy();
      this.provider.once('registration_delete.success', spy);

      return this.agent.del(`/reg/${client.client_id}`)
        .auth(client.registration_access_token, { type: 'bearer' })
        .expect(204)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        });
    });

    it('cannot delete non-dynamic clients', async function () {
      const rat = new (this.provider.RegistrationAccessToken)({ clientId: 'client' });
      const bearer = await rat.save();
      return this.agent.del('/reg/client')
        .auth(bearer, { type: 'bearer' })
        .expect(403)
        .expect((response) => {
          expect(response.body).to.eql({
            error: 'invalid_request',
            error_description: 'this client is not allowed to delete itself',
          });
        });
    });
  });
});
