import { describe, before, beforeEach, it, after } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';
import Provider, { errors } from '../../lib/index.js';

const sinon = createSandbox();

describe('client registration policies', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  beforeEach(() => sinon.restore(), { timeout: 3000 });

  describe('configuration', () => {
    it('must only be enabled in conjunction with adapter-backed initial access tokens', { timeout: 3000 }, () => {
      assert.throws(() => {
        new Provider('http://localhost', {
          features: {
            registration: {
              enabled: true,
              policies: { foo() {} },
            },
          },
        });
      }, (error) => { assert.ok(error.message.includes('registration policies are only available in conjunction with adapter-backed initial access tokens')); return true; });
    });
  });

  describe('Registration & InitialAccessToken', () => {
    const fixture2 = Object.create(fixture);

    it('allows policies to run to be stored on an InitialAccessToken', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture2.provider.once('initial_access_token.saved', spy);
      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['empty-policy'],
      }).save();

      assert.equal(spy.called, true);
      ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, ['empty-policy']); })(spy.args[0][0]);

      ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, [
        'empty-policy',
      ]); })(await fixture2.provider.InitialAccessToken.find(value));
    });

    it('runs the policies when a client is getting created', { timeout: 3000 }, async () => {
      const spy = sinon.spy(
        i(fixture2.provider).features.registration.policies,
        'empty-policy',
      );
      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['empty-policy'],
      }).save();

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
    });

    it('allows for policies to set property defaults', { timeout: 3000 }, async () => {
      i(fixture2.provider).features.registration.policies['set-default'] = (
        _ctx,
        properties,
      ) => {
        if (!('id_token_signed_response_alg' in properties)) {
          properties.id_token_signed_response_alg = 'HS256';
        }
      };

      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['set-default'],
      }).save();

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201)
        .expect(({ body }) => {
          ((actual) => { assert.ok('id_token_signed_response_alg' in Object(actual)); assert.equal(actual.id_token_signed_response_alg, 'HS256'); })(body);
        });

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
          id_token_signed_response_alg: 'PS256',
        })
        .expect(201)
        .expect(({ body }) => {
          ((actual) => { assert.ok('id_token_signed_response_alg' in Object(actual)); assert.equal(actual.id_token_signed_response_alg, 'PS256'); })(body);
        });
    });

    it('allows for policies to force property values', { timeout: 3000 }, async () => {
      i(fixture2.provider).features.registration.policies['force-default'] = (
        _ctx,
        properties,
      ) => {
        properties.id_token_signed_response_alg = 'HS256';
      };

      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['force-default'],
      }).save();

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
          id_token_signed_response_alg: 'PS256',
        })
        .expect(201)
        .expect(({ body }) => {
          ((actual) => { assert.ok('id_token_signed_response_alg' in Object(actual)); assert.equal(actual.id_token_signed_response_alg, 'HS256'); })(body);
        });
    });

    it('allows for policies to validate property values', { timeout: 3000 }, async () => {
      i(fixture2.provider).features.registration.policies['throw-error'] = () => {
        throw new errors.InvalidClientMetadata('foo');
      };

      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['throw-error'],
      }).save();

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({
          redirect_uris: ['https://rp.example.com/cb'],
          id_token_signed_response_alg: 'PS256',
        })
        .expect(400)
        .expect(({ body }) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client_metadata'); })(body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'foo'); })(body);
        });
    });

    it('pushes the policy down to the registration access token', { timeout: 3000 }, async () => {
      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['empty-policy'],
      }).save();

      const spy = sinon.spy();
      fixture2.provider.once('registration_access_token.saved', spy);

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, ['empty-policy']); })(spy.args[0][0]);
    });

    it('can be done to push different policies to rat', { timeout: 3000 }, async () => {
      i(fixture2.provider).features.registration.policies['change-rat-policy'] = async (ctx) => {
        ctx.oidc.entities.RegistrationAccessToken.policies = ['empty-policy'];
      };

      const value = await new fixture2.provider.InitialAccessToken({
        policies: ['change-rat-policy'],
      }).save();

      const spy = sinon.spy();
      fixture2.provider.once('registration_access_token.saved', spy);

      await fixture2.agent
        .post('/reg')
        .auth(value, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, ['empty-policy']); })(spy.args[0][0]);
    });

    it('policies must be an array', { timeout: 3000 }, async () => {
      await assert.rejects(
        new fixture2.provider.InitialAccessToken({ policies: null }).save(),
        (err) => {
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be an array'); })(err);
          return true;
        },
      );
      const saved = await new fixture2.provider.InitialAccessToken({ policies: undefined }).save();
      fixture2.TestAdapter.for('InitialAccessToken').syncUpdate(fixture2.getTokenJti(saved), {
        policies: null,
      });

      return assert.rejects(fixture2.provider.InitialAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be an array'); })(err);
        return true;
      });
    });

    it('policies array must have members', { timeout: 3000 }, async () => {
      await assert.rejects(new fixture2.provider.InitialAccessToken({ policies: [] }).save(), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must not be empty'); })(err);
        return true;
      });
      const saved = await new fixture2.provider.InitialAccessToken({ policies: undefined }).save();
      fixture2.TestAdapter.for('InitialAccessToken').syncUpdate(fixture2.getTokenJti(saved), {
        policies: [],
      });

      return assert.rejects(fixture2.provider.InitialAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must not be empty'); })(err);
        return true;
      });
    });

    it('policies members must be strings', { timeout: 3000 }, async () => {
      await assert.rejects(
        new fixture2.provider.InitialAccessToken({ policies: [null] }).save(),
        (err) => {
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be strings'); })(err);
          return true;
        },
      );
      const saved = await new fixture2.provider.InitialAccessToken({ policies: undefined }).save();
      fixture2.TestAdapter.for('InitialAccessToken').syncUpdate(fixture2.getTokenJti(saved), {
        policies: [null],
      });

      return assert.rejects(fixture2.provider.InitialAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be strings'); })(err);
        return true;
      });
    });

    it('policies members must be present in the provider configuration', { timeout: 3000 }, async () => {
      await assert.rejects(
        new fixture2.provider.InitialAccessToken({ policies: ['foo-bar'] }).save(),
        (err) => {
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policy foo-bar not configured'); })(err);
          return true;
        },
      );
      const saved = await new fixture2.provider.InitialAccessToken({ policies: undefined }).save();
      fixture2.TestAdapter.for('InitialAccessToken').syncUpdate(fixture2.getTokenJti(saved), {
        policies: ['foo-bar'],
      });

      return assert.rejects(fixture2.provider.InitialAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policy foo-bar not configured'); })(err);
        return true;
      });
    });
  });

  describe('Registration Management & RegistrationAccessToken', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(async () => {
      const iat = await new fixture3.provider.InitialAccessToken({}).save();
      await fixture3.agent
        .post('/reg')
        .auth(iat, { type: 'bearer' })
        .send({ redirect_uris: ['https://rp.example.com/cb'] })
        .expect(201)
        .expect(
          ({
            body: {
              registration_access_token,
              registration_client_uri,
              client_secret_expires_at,
              client_id_issued_at,
              ...body
            },
          }) => {
            fixture3.rat = registration_access_token;
            fixture3.url = url.parse(registration_client_uri).pathname;
            fixture3.body = body;
          },
        );
    }, { timeout: 3000 });

    it('runs the policies when a client is getting updated', { timeout: 3000 }, async () => {
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(fixture3.rat), {
        policies: ['empty-policy'],
      });
      const spy = sinon.spy(
        i(fixture3.provider).features.registration.policies,
        'empty-policy',
      );

      await fixture3.agent
        .put(fixture3.url)
        .auth(fixture3.rat, { type: 'bearer' })
        .send(fixture3.body)
        .type('json')
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
    });

    it('allows for policies to set property defaults', { timeout: 3000 }, async () => {
      i(fixture3.provider).features.registration.policies['set-default'] = (
        _ctx,
        properties,
      ) => {
        if (!('client_name' in properties)) {
          properties.client_name = 'foobar';
        }
      };
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(fixture3.rat), {
        policies: ['set-default'],
      });

      await fixture3.agent
        .put(fixture3.url)
        .auth(fixture3.rat, { type: 'bearer' })
        .send(fixture3.body)
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('client_name' in Object(actual)); assert.equal(actual.client_name, 'foobar'); })(body);
        });

      await fixture3.agent
        .put(fixture3.url)
        .auth(fixture3.rat, { type: 'bearer' })
        .send({
          ...fixture3.body,
          client_name: 'foobarbaz',
        })
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('client_name' in Object(actual)); assert.equal(actual.client_name, 'foobarbaz'); })(body);
        });
    });

    it('allows for policies to force property values', { timeout: 3000 }, async () => {
      i(fixture3.provider).features.registration.policies['force-value'] = (
        _ctx,
        properties,
      ) => {
        properties.client_name = 'foobar';
      };
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(fixture3.rat), {
        policies: ['force-value'],
      });

      await fixture3.agent
        .put(fixture3.url)
        .auth(fixture3.rat, { type: 'bearer' })
        .send({
          ...fixture3.body,
          client_name: 'foobarbaz',
        })
        .type('json')
        .expect(200)
        .expect(({ body }) => {
          ((actual) => { assert.ok('client_name' in Object(actual)); assert.equal(actual.client_name, 'foobar'); })(body);
        });
    });

    it('allows for policies to validate property values', { timeout: 3000 }, async () => {
      i(fixture3.provider).features.registration.policies['throw-error'] = () => {
        throw new errors.InvalidClientMetadata('foo');
      };
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(fixture3.rat), {
        policies: ['throw-error'],
      });

      await fixture3.agent
        .put(fixture3.url)
        .auth(fixture3.rat, { type: 'bearer' })
        .send(fixture3.body)
        .type('json')
        .expect(400)
        .expect(({ body }) => {
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client_metadata'); })(body);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'foo'); })(body);
        });
    });

    describe('rotateRegistrationAccessToken', () => {
      const fixture4 = Object.create(fixture3);

      before(() => {
        const conf = i(fixture4.provider).configuration;
        conf.features.registrationManagement = { rotateRegistrationAccessToken: true };
      }, { timeout: 3000 });

      after(() => {
        const conf = i(fixture4.provider).configuration;
        conf.features.registrationManagement = { rotateRegistrationAccessToken: false };
      }, { timeout: 3000 });

      it('pushes the same policies down to the rotated registration access token', { timeout: 3000 }, async () => {
        fixture4.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture4.getTokenJti(fixture4.rat), {
          policies: ['empty-policy'],
        });

        const spy = sinon.spy();
        fixture4.provider.once('registration_access_token.saved', spy);

        let value;
        await fixture4.agent
          .put(fixture4.url)
          .auth(fixture4.rat, { type: 'bearer' })
          .send(fixture4.body)
          .type('json')
          .expect(200)
          .expect(({ body }) => {
            value = body.registration_access_token;
          });

        assert.equal(spy.called, true);
        ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, ['empty-policy']); })(spy.args[0][0]);

        ((actual) => { assert.ok('policies' in Object(actual)); assert.deepEqual(actual.policies, ['empty-policy']); })(await fixture4.provider.RegistrationAccessToken.find(value));
      });
    });

    it('policies must be an array', { timeout: 3000 }, async () => {
      const saved = await new fixture3.provider.RegistrationAccessToken({ policies: undefined }).save();
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(saved), {
        policies: null,
      });

      return assert.rejects(fixture3.provider.RegistrationAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be an array'); })(err);
        return true;
      });
    });

    it('policies array must have members', { timeout: 3000 }, async () => {
      const saved = await new fixture3.provider.RegistrationAccessToken({ policies: undefined }).save();
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(saved), {
        policies: [],
      });

      return assert.rejects(fixture3.provider.RegistrationAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must not be empty'); })(err);
        return true;
      });
    });

    it('policies members must be strings', { timeout: 3000 }, async () => {
      const saved = await new fixture3.provider.RegistrationAccessToken({ policies: undefined }).save();
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(saved), {
        policies: [null],
      });

      return assert.rejects(fixture3.provider.RegistrationAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policies must be strings'); })(err);
        return true;
      });
    });

    it('policies members must be present in the provider configuration', { timeout: 3000 }, async () => {
      const saved = await new fixture3.provider.RegistrationAccessToken({ policies: undefined }).save();
      fixture3.TestAdapter.for('RegistrationAccessToken').syncUpdate(fixture3.getTokenJti(saved), {
        policies: ['foo-bar'],
      });

      return assert.rejects(fixture3.provider.RegistrationAccessToken.find(saved), (err) => {
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'policy foo-bar not configured'); })(err);
        return true;
      });
    });
  });
});
