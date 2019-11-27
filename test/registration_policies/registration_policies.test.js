/* eslint-disable no-param-reassign */

const url = require('url');

const sinon = require('sinon').createSandbox();
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const { Provider } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('client registration policies', () => {
  before(bootstrap(__dirname));
  beforeEach(sinon.restore);

  describe('configuration', () => {
    it('must only be enabled in conjuction with adapter-backed initial access tokens', () => {
      expect(() => {
        new Provider('http://localhost', { // eslint-disable-line no-new
          features: {
            registration: {
              enabled: true,
              policies: { foo() { } },
            },
          },
        });
      }).to.throw('registration policies are only available in conjuction with adapter-backed initial access tokens');
    });
  });

  describe('Registration & InitialAccessToken', () => {
    it('allows policies to run to be stored on an InitialAccessToken', async function () {
      const spy = sinon.spy();
      this.provider.once('initial_access_token.saved', spy);
      const value = await new this.provider.InitialAccessToken({ policies: ['empty-policy'] }).save();

      expect(spy.called).to.be.true;
      expect(spy.args[0][0]).to.have.deep.property('policies', ['empty-policy']);

      expect(await this.provider.InitialAccessToken.find(value)).to.have.deep.property('policies', ['empty-policy']);
    });

    it('runs the policies when a client is getting created', async function () {
      const spy = sinon.spy(i(this.provider).configuration('features.registration.policies'), 'empty-policy');
      const value = await new this.provider.InitialAccessToken({ policies: ['empty-policy'] }).save();

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      expect(spy).to.have.property('calledOnce', true);
    });

    it('allows for policies to set property defaults', async function () {
      i(this.provider).configuration('features.registration.policies')['set-default'] = (ctx, properties) => {
        if (!('id_token_signed_response_alg' in properties)) {
          properties.id_token_signed_response_alg = 'HS256';
        }
      };

      const value = await new this.provider.InitialAccessToken({ policies: ['set-default'] }).save();

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201)
        .expect(({ body }) => {
          expect(body).to.have.property('id_token_signed_response_alg', 'HS256');
        });

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'], id_token_signed_response_alg: 'PS256' })
        .expect(201)
        .expect(({ body }) => {
          expect(body).to.have.property('id_token_signed_response_alg', 'PS256');
        });
    });

    it('allows for policies to force property values', async function () {
      i(this.provider).configuration('features.registration.policies')['force-default'] = (ctx, properties) => {
        properties.id_token_signed_response_alg = 'HS256';
      };

      const value = await new this.provider.InitialAccessToken({ policies: ['force-default'] }).save();

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'], id_token_signed_response_alg: 'PS256' })
        .expect(201)
        .expect(({ body }) => {
          expect(body).to.have.property('id_token_signed_response_alg', 'HS256');
        });
    });

    it('allows for policies to validate property values', async function () {
      i(this.provider).configuration('features.registration.policies')['throw-error'] = () => {
        throw new Provider.errors.InvalidClientMetadata('foo');
      };

      const value = await new this.provider.InitialAccessToken({ policies: ['throw-error'] }).save();

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'], id_token_signed_response_alg: 'PS256' })
        .expect(400)
        .expect(({ body }) => {
          expect(body).to.have.property('error', 'invalid_client_metadata');
          expect(body).to.have.property('error_description', 'foo');
        });
    });

    it('pushes the policy down to the registration access token', async function () {
      const value = await new this.provider.InitialAccessToken({ policies: ['empty-policy'] }).save();

      const spy = sinon.spy();
      this.provider.once('registration_access_token.saved', spy);

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][0]).to.have.deep.property('policies', ['empty-policy']);
    });

    it('can be done to push different policies to rat', async function () {
      i(this.provider).configuration('features.registration.policies')['change-rat-policy'] = async (ctx) => {
        ctx.oidc.entities.RegistrationAccessToken.policies = ['empty-policy'];
      };

      const value = await new this.provider.InitialAccessToken({ policies: ['change-rat-policy'] }).save();

      const spy = sinon.spy();
      this.provider.once('registration_access_token.saved', spy);

      await this.agent.post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][0]).to.have.deep.property('policies', ['empty-policy']);
    });

    it('policies must be an array', async function () {
      await new this.provider.InitialAccessToken({ policies: null }).save().then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be an array');
      });
      const saved = await new this.provider.InitialAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('InitialAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: null,
      });

      await this.provider.InitialAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be an array');
      });
    });

    it('policies array must have members', async function () {
      await new this.provider.InitialAccessToken({ policies: [] }).save().then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must not be empty');
      });
      const saved = await new this.provider.InitialAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('InitialAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: [],
      });

      await this.provider.InitialAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must not be empty');
      });
    });

    it('policies members must be strings', async function () {
      await new this.provider.InitialAccessToken({ policies: [null] }).save().then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be strings');
      });
      const saved = await new this.provider.InitialAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('InitialAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: [null],
      });

      await this.provider.InitialAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be strings');
      });
    });

    it('policies members must be present in the provider configuration', async function () {
      await new this.provider.InitialAccessToken({ policies: ['foo-bar'] }).save().then(fail, (err) => {
        expect(err).to.have.property('message', 'policy foo-bar not configured');
      });
      const saved = await new this.provider.InitialAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('InitialAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: ['foo-bar'],
      });

      await this.provider.InitialAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policy foo-bar not configured');
      });
    });
  });

  describe('Registration Management & RegistrationAccessToken', () => {
    beforeEach(async function () {
      const iat = await new this.provider.InitialAccessToken({}).save();
      await this.agent.post('/reg')
        .auth(iat, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201)
        .expect(({
          body: {
            registration_access_token,
            registration_client_uri,
            client_secret_expires_at,
            client_id_issued_at,
            ...body
          },
        }) => {
          this.rat = registration_access_token;
          this.url = url.parse(registration_client_uri).pathname;
          this.body = body;
        });
    });

    it('runs the policies when a client is getting updated', async function () {
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(this.rat), {
        policies: ['empty-policy'],
      });
      const spy = sinon.spy(i(this.provider).configuration('features.registration.policies'), 'empty-policy');

      await this.agent.put(this.url)
        .auth(this.rat, { type: 'bearer' })
        .send(this.body)
        .type('json')
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
    });

    it('allows for policies to set property defaults', async function () {
      i(this.provider).configuration('features.registration.policies')['set-default'] = (ctx, properties) => {
        if (!('client_name' in properties)) {
          properties.client_name = 'foobar';
        }
      };
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(this.rat), {
        policies: ['set-default'],
      });

      await this.agent.put(this.url)
        .auth(this.rat, { type: 'bearer' })
        .send(this.body)
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('client_name', 'foobar');
        });

      await this.agent.put(this.url)
        .auth(this.rat, { type: 'bearer' })
        .send({
          ...this.body,
          client_name: 'foobarbaz',
        })
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('client_name', 'foobarbaz');
        });
    });

    it('allows for policies to force property values', async function () {
      i(this.provider).configuration('features.registration.policies')['force-value'] = (ctx, properties) => {
        properties.client_name = 'foobar';
      };
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(this.rat), {
        policies: ['force-value'],
      });

      await this.agent.put(this.url)
        .auth(this.rat, { type: 'bearer' })
        .send({
          ...this.body,
          client_name: 'foobarbaz',
        })
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('client_name', 'foobar');
        });
    });

    it('allows for policies to validate property values', async function () {
      i(this.provider).configuration('features.registration.policies')['throw-error'] = () => {
        throw new Provider.errors.InvalidClientMetadata('foo');
      };
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(this.rat), {
        policies: ['throw-error'],
      });

      await this.agent.put(this.url)
        .auth(this.rat, { type: 'bearer' })
        .send(this.body)
        .type('json')
        .expect(400)
        .expect(({ body }) => {
          expect(body).to.have.property('error', 'invalid_client_metadata');
          expect(body).to.have.property('error_description', 'foo');
        });
    });

    describe('rotateRegistrationAccessToken', () => {
      before(function () {
        const conf = i(this.provider).configuration();
        conf.features.registrationManagement = { rotateRegistrationAccessToken: true };
      });

      after(function () {
        const conf = i(this.provider).configuration();
        conf.features.registrationManagement = { rotateRegistrationAccessToken: false };
      });

      it('pushes the same policies down to the rotated registration access token', async function () {
        this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(this.rat), {
          policies: ['empty-policy'],
        });

        const spy = sinon.spy();
        this.provider.once('registration_access_token.saved', spy);

        let value;
        await this.agent.put(this.url)
          .auth(this.rat, { type: 'bearer' })
          .send(this.body)
          .type('json')
          .expect(200)
          .expect(({ body }) => {
            value = body.registration_access_token;
          });

        expect(spy.called).to.be.true;
        expect(spy.args[0][0]).to.have.deep.property('policies', ['empty-policy']);

        expect(await this.provider.RegistrationAccessToken.find(value)).to.have.deep.property('policies', ['empty-policy']);
      });
    });

    it('policies must be an array', async function () {
      const saved = await new this.provider.RegistrationAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: null,
      });

      await this.provider.RegistrationAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be an array');
      });
    });

    it('policies array must have members', async function () {
      const saved = await new this.provider.RegistrationAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: [],
      });

      await this.provider.RegistrationAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must not be empty');
      });
    });

    it('policies members must be strings', async function () {
      const saved = await new this.provider.RegistrationAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: [null],
      });

      await this.provider.RegistrationAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policies must be strings');
      });
    });

    it('policies members must be present in the provider configuration', async function () {
      const saved = await new this.provider.RegistrationAccessToken({ policies: undefined }).save();
      this.TestAdapter.for('RegistrationAccessToken').syncUpdate(this.getTokenJti(saved), {
        policies: ['foo-bar'],
      });

      await this.provider.RegistrationAccessToken.find(saved).then(fail, (err) => {
        expect(err).to.have.property('message', 'policy foo-bar not configured');
      });
    });
  });
});
