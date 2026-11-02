import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import * as util from 'node:util';

import sinon from 'sinon';
import merge from 'lodash/merge.js';
import mergeWith from 'lodash/mergeWith.js';
import omit from 'lodash/omit.js';
import pull from 'lodash/pull.js';
import cloneDeep from 'lodash/cloneDeep.js';

import Provider, { errors } from '../../lib/index.js';
import { enabledJWA } from '../default.config.js';
import sectorIdentifier from '../../lib/helpers/sector_identifier.js';
import keys, { stripPrivateJWKFields } from '../keys.js';
import addClient from '../../lib/helpers/add_client.js';

const sigKey = stripPrivateJWKFields(keys[0]);
const privateKey = keys[0];
const { InvalidClientMetadata } = errors;

const pqc = [];
for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  if (SubtleCrypto.supports?.('generateKey', alg)) {
    pqc.push(alg);
  }
}

describe('Client metadata validation', () => {

  let DefaultProvider;
  before(() => {
    DefaultProvider = new Provider('http://localhost', {
      jwks: { keys },
      enabledJWA: cloneDeep(enabledJWA),
    });
  }, { timeout: 3000 });

  function register(metadata, configuration) {
    let provider;
    if (configuration) {
      provider = new Provider(
        'http://localhost',
        mergeWith(
          {
            jwks: { keys },
            enabledJWA: cloneDeep(enabledJWA),
          },
          configuration,
          (objValue, srcValue) => {
            if (Array.isArray(objValue)) {
              return srcValue;
            }
            return undefined;
          },
        ),
      );
    } else {
      provider = DefaultProvider;
    }

    return addClient(provider, {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      ...metadata,
    });
  }

  it('rejects sparse and inherited string-array metadata entries', { timeout: 3000 }, async () => {
    const inherited = Array(1);
    const prototype = Object.create(Array.prototype);
    Object.defineProperty(prototype, '0', { enumerable: true, value: 'code' });
    Object.setPrototypeOf(inherited, prototype);

    for (const [property, configuration] of [
      ['contacts'],
      ['response_types'],
      [
        'id_token_signing_alg_values_supported',
        { features: { rpMetadataChoices: { enabled: true } } },
      ],
    ]) {
      for (const value of [Array(1), inherited]) {
        await assert.rejects(
          register({ [property]: value }, configuration),
          (error) => {
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, `${property} must only contain strings`); })(error);
            return true;
          },
        );
      }
    }
  });

  const mustBeString = (
    prop,
    values = [[], 123, true, null, false, {}, ''],
    metadata,
    configuration,
  ) => {
    values.forEach((value) => {
      let msg = util.format('must be a string, %j provided', value);
      if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, { timeout: 3000 }, () => assert.rejects(register({ ...metadata, [prop]: value }, configuration), (err) => {
        if (prop === 'redirect_uris') {
          assert.equal(err.message, 'invalid_redirect_uri');
        } else {
          assert.equal(err.message, 'invalid_client_metadata');
        }
        assert.equal(err.error_description, `${prop} must be a non-empty string if provided`);
        return true;
      }));
    });
  };

  const mustBeUri = (prop, protocols, configuration, metadata) => {
    it('must be a uri', { timeout: 3000 }, () => assert.rejects(
      register(
        {
          ...metadata,
          [prop]: 'whatever://not but not a uri',
        },
        configuration,
      ),
      (err) => {
        if (prop === 'redirect_uris') {
          assert.equal(err.message, 'invalid_redirect_uri');
        } else {
          assert.equal(err.message, 'invalid_client_metadata');
        }
        if (protocols.length === 1 && protocols[0] === 'https') {
          assert.equal(err.error_description, `${prop} must be a https uri`);
        } else {
          assert.equal(err.error_description, `${prop} must be a web uri`);
        }
        return true;
      },
    ));

    protocols.forEach((protocol) => {
      it(`can be ${protocol} uri`, { timeout: 3000 }, () => register({
        [prop]: `${protocol}://example.com/${prop}`,
      }));
    });
  };

  const mustBeArray = (prop, values = [{}, 'string', 123, true, null, false], configuration) => {
    values.forEach((value) => {
      let msg = util.format('must be a array, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, { timeout: 3000 }, () => assert.rejects(
        register(
          {
            [prop]: value,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            assert.equal(err.message, 'invalid_redirect_uri');
          } else {
            assert.equal(err.message, 'invalid_client_metadata');
          }
          assert.equal(err.error_description, `${prop} must be an array`);
          return true;
        },
      ));
    });
  };

  const mustBeBoolean = (prop, metadata, configuration) => {
    [{}, 'string', 123, null, []].forEach((value) => {
      let msg = util.format('must be a boolean, %j provided', value);
      if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, { timeout: 3000 }, () => assert.rejects(
        register(
          {
            [prop]: value,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            assert.equal(err.message, 'invalid_redirect_uri');
          } else {
            assert.equal(err.message, 'invalid_client_metadata');
          }
          assert.equal(err.error_description, `${prop} must be a boolean`);
          return true;
        },
      ));
    });
  };

  const defaultsTo = (prop, value, metadata, configuration, additionalAssertion) => {
    let msg = util.format('defaults to %s', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);

    it(msg, { timeout: 3000 }, () => register(metadata, configuration).then((client) => {
      if (value === undefined) {
        assert.ok(!(prop in Object(client.metadata())));
      } else {
        ((actual) => { assert.ok(prop in Object(actual)); assert.deepEqual(actual[prop], value); })(client.metadata());
      }

      if (additionalAssertion) {
        return additionalAssertion(client);
      }

      return undefined;
    }));
  };

  const isRequired = (prop, values, configuration, metadata) => {
    (values || [null, undefined, '']).forEach((value) => {
      let msg = util.format('is required, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, { timeout: 3000 }, () => assert.rejects(
        register(
          {
            [prop]: value,
            ...metadata,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            assert.equal(err.message, 'invalid_redirect_uri');
          } else {
            assert.equal(err.message, 'invalid_client_metadata');
          }
          assert.equal(err.error_description, `${prop} is mandatory property`);
          return true;
        },
      ));
    });
  };

  const allows = (
    prop,
    value,
    metadata,
    configuration,
    assertion = (client) => {
      assert.deepEqual(client.metadata()[prop], value);
    },
  ) => {
    let msg = util.format('passes %j', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    it(msg, { timeout: 3000 }, () => register({ ...metadata, [prop]: value }, configuration).then(assertion, (err) => {
      if (err instanceof InvalidClientMetadata) {
        throw new Error(`InvalidClientMetadata received ${err.message} ${err.error_description}`);
      }
    }));
  };

  const rejects = (prop, value, description, metadata, configuration) => {
    let msg = util.format('rejects %j', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    it(msg, { timeout: 3000 }, () => assert.rejects(register({ ...metadata, [prop]: value }, configuration), (err) => {
      if (prop === 'redirect_uris') {
        assert.equal(err.message, 'invalid_redirect_uri');
      } else {
        assert.equal(err.message, 'invalid_client_metadata');
      }
      if (description) {
        assert[description.exec ? 'match' : 'equal'](err.error_description, description);
      }
      return true;
    }));
  };

  describe('application_type', () => {

    defaultsTo('application_type', 'web');
    mustBeString('application_type');

    allows('application_type', 'web');
    allows('application_type', 'native', {
      redirect_uris: ['com.example.myapp:/localhost/redirect'],
    });
    rejects('application_type', 'foobar', "application_type must be 'native' or 'web'");
  });

  describe('client_id', () => {

    isRequired('client_id');
    mustBeString('client_id', [123, {}, [], true]);

    allows('client_id', 'whatever client id');
    rejects('client_id', '£', 'invalid client_id value');
  });

  describe('client_name', () => {

    mustBeString('client_name');
    allows('client_name', 'whatever client name');
  });

  describe('client_secret', () => {

    isRequired('client_secret');
    mustBeString('client_secret', [123, {}, [], true]);
    allows('client_secret', 'whatever client secret');
    rejects('client_secret', '£', 'invalid client_secret value');
    // must of certain length => GOTO: client_secrets.test.js
  });

  describe('contacts', () => {

    mustBeArray('contacts');
    allows('contacts', ['developer@example.com', 'info@example.com', 'info+some@example.com']);
    allows('contacts', ["o'connor@example.com"]);
    rejects('contacts', [123], /must only contain strings$/);
    rejects('contacts', ['john doe'], 'contacts can only contain email addresses');
    rejects('contacts', ['o\u2019connor@example.com'], 'contacts can only contain email addresses');
  });

  describe('default_acr_values', () => {

    mustBeArray('default_acr_values');
    const acrValues = ['0', '1', '2'];

    allows('default_acr_values', []);
    acrValues.forEach((value) => {
      allows('default_acr_values', [value], undefined, { acrValues });
    });
    allows('default_acr_values', acrValues, undefined, { acrValues });
    rejects('default_acr_values', [123], /must only contain strings$/);
    rejects(
      'default_acr_values',
      ['not a member'],
      'default_acr_values must be empty (no values are allowed)',
    );
    rejects('default_acr_values', [
      'not a member',
      '1',
      'default_acr_values must be empty (no values are allowed)',
    ]);
    rejects(
      'default_acr_values',
      ['not a member'],
      "default_acr_values can only contain '0', '1', or '2'",
      undefined,
      { acrValues },
    );
    rejects(
      'default_acr_values',
      ['not a member', '1'],
      "default_acr_values can only contain '0', '1', or '2'",
      undefined,
      { acrValues },
    );
  });

  describe('require_signed_request_object', () => {

    const configuration = (value = false, enabled = true) => ({
      features: {
        requestObjects: {
          enabled,
          requireSignedRequestObject: value,
        },
        pushedAuthorizationRequests: {
          enabled: false,
        },
      },
    });
    mustBeBoolean('require_signed_request_object', undefined, configuration());
    defaultsTo('require_signed_request_object', undefined, undefined, configuration(false, false));
    defaultsTo('require_signed_request_object', false, undefined, configuration());
    defaultsTo('require_signed_request_object', true, undefined, configuration(true));
    defaultsTo(
      'require_signed_request_object',
      true,
      {
        require_signed_request_object: false,
      },
      configuration(true),
    );
    defaultsTo('require_signed_request_object', true, undefined, {
      ...configuration(),
      clientDefaults: { require_signed_request_object: true },
    });
  });

  describe('default_max_age', () => {

    allows('default_max_age', 5);
    allows('default_max_age', 0);
    rejects('default_max_age', Number.MAX_SAFE_INTEGER + 1);
    rejects('default_max_age', -1);
    rejects('default_max_age', true);
    rejects('default_max_age', 'string');
    rejects('default_max_age', {});
    rejects('default_max_age', []);
  });

  describe('grant_types', () => {

    defaultsTo('grant_types', ['authorization_code']);
    mustBeArray('grant_types');
    allows('grant_types', ['authorization_code', 'refresh_token']);
    allows('grant_types', [], { response_types: ['none'] });
    rejects('grant_types', [123], /must only contain strings$/);
    rejects('grant_types', ['not-a-type']);

    // grant types auto-fixup
    allows('grant_types', [], undefined, undefined, (client) => {
      ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['authorization_code']); })(client.metadata());
    });
    allows('grant_types', ['implicit'], {
      // misses authorization_code
      response_types: ['id_token', 'code'],
    }, undefined, (client) => {
      ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['implicit', 'authorization_code']); })(client.metadata());
    });
    allows('grant_types', ['authorization_code'], {
      // misses code in response_types
      response_types: ['id_token'],
    }, undefined, (client) => {
      ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['implicit']); })(client.metadata());
    });
    allows('grant_types', ['authorization_code', 'implicit'], {
      // misses token or id_token in response_types
      response_types: ['code'],
    }, undefined, (client) => {
      ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, ['authorization_code']); })(client.metadata());
    });
  });

  describe('id_token_signed_response_alg', () => {

    defaultsTo('id_token_signed_response_alg', 'RS256');
    mustBeString('id_token_signed_response_alg');
    rejects('id_token_signed_response_alg', 'none', undefined, {
      response_types: ['code id_token'],
    });
    rejects('id_token_signed_response_alg', 'none');
  });

  ['client_uri', 'logo_uri', 'policy_uri', 'tos_uri'].forEach((prop) => {
    describe(prop, () => {

      mustBeString(prop);
      mustBeUri(prop, ['http', 'https']);
    });
  });

  describe('initiate_login_uri', () => {

    mustBeString('initiate_login_uri');
    mustBeUri('initiate_login_uri', ['https']);
  });

  describe('scope', () => {

    mustBeString('scope');
    allows('scope', undefined);
    allows('scope', 'openid');
    allows('scope', 'offline_access');
    allows('scope', 'openid offline_access');
    allows('scope', 'openid profile', undefined, { scopes: ['profile'] });
    allows('scope', 'openid profile', undefined, { claims: { profile: ['given_name'] } });
    allows('scope', 'profile', undefined, { scopes: ['profile'] });
    allows('scope', 'profile', undefined, { claims: { profile: ['given_name'] } });
    rejects(
      'scope',
      'foo',
      'scope must only contain Authorization Server supported scope values',
    );
  });

  describe('redirect_uris', () => {

    isRequired('redirect_uris');
    mustBeArray('redirect_uris', [{}, 'string', 123, true]);
    rejects('redirect_uris', [123], /must only contain strings$/);
    rejects('redirect_uris', [], /must contain members$/);

    allows('redirect_uris', ['http://some'], {
      application_type: 'web',
    });
    allows('redirect_uris', ['https://some'], {
      application_type: 'web',
    });
    describe('PAR allowUnregisteredRedirectUris', () => {
      allows('redirect_uris', [], {
        require_pushed_authorization_requests: true,
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: true } } });
      allows('redirect_uris', [], {
        application_type: 'native',
        require_pushed_authorization_requests: true,
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: true } } });
      rejects('redirect_uris', [], /redirect_uris must contain members/, {
        require_pushed_authorization_requests: true,
      }, {
        features: {
          pushedAuthorizationRequests: { enabled: false, allowUnregisteredRedirectUris: true },
        },
      });
      rejects('redirect_uris', [], /redirect_uris must contain members/, {
        require_pushed_authorization_requests: true,
        token_endpoint_auth_method: 'none',
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: true } } });
      rejects('redirect_uris', [], /redirect_uris must contain members/, {
        require_pushed_authorization_requests: true,
        sector_identifier_uri: 'https://foobar.example.com/sector',
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: true } } });
      rejects('redirect_uris', [], /redirect_uris must contain members/, {
        require_pushed_authorization_requests: true,
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: false } } });
      rejects('redirect_uris', [], /redirect_uris must contain members/, {
        require_pushed_authorization_requests: false,
      }, { features: { pushedAuthorizationRequests: { allowUnregisteredRedirectUris: true } } });
    });
    rejects(
      'redirect_uris',
      ['https://rp.example.com#whatever'],
      /redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects(
      'redirect_uris',
      ['https://rp.example.com#'],
      /redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects('redirect_uris', ['no-dot-reverse-notation:/some'], undefined, {
      application_type: 'web',
    });
    rejects('redirect_uris', ['https://localhost'], undefined, {
      application_type: 'web',
      grant_types: ['implicit', 'authorization_code'],
      response_types: ['code id_token'],
    });
    allows('redirect_uris', ['http://localhost'], {
      application_type: 'web',
    });
    rejects('redirect_uris', ['http://some'], undefined, {
      application_type: 'native',
    });
    rejects('redirect_uris', ['not-a-uri'], undefined, {
      application_type: 'native',
    });
    rejects('redirect_uris', ['https://localhost/op/callback'], /for native clients using claimed HTTPS URIs must not be using localhost as hostname/, {
      application_type: 'native',
    });
    allows('redirect_uris', ['com.example.app://localhost/op/callback', 'com.example.app:/op/callback'], {
      application_type: 'native',
    });
    allows('redirect_uris', ['myapp:/op/callback'], {
      application_type: 'native',
    });
    allows('redirect_uris', ['cursor://anysphere.cursor-mcp/oauth/callback'], {
      application_type: 'native',
    });
    rejects('redirect_uris', ['http://foo/bar'], undefined, {
      application_type: 'web',
      grant_types: ['implicit'],
      response_types: ['id_token'],
    });
    for (const scheme of ['javascript', 'vbscript', 'data', 'blob', 'file', 'about']) {
      rejects('redirect_uris', [`${scheme}:foo`], `redirect_uris must not use the ${scheme} URI scheme`, {
        application_type: 'native',
      });
    }
    it('has an schema invalidation hook for forcing https on implicit', { timeout: 3000 }, async () => {
      const sandbox = sinon.createSandbox();
      sandbox.spy(DefaultProvider.Client.Schema.prototype, 'invalidate');
      await register({
        grant_types: ['implicit'],
        response_types: ['id_token'],
        redirect_uris: ['http://foo/bar'],
      })
        .then(
          () => {
            assert(false);
          },
          () => {
            const spy = DefaultProvider.Client.Schema.prototype.invalidate;
            ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
            const call = spy.getCall(0);
            const [, code] = call.args;
            assert.deepEqual(code, 'implicit-force-https');
          },
        )
        .finally(() => {
          sandbox.restore();
        });
    });
    it('has an schema invalidation hook for preventing localhost', { timeout: 3000 }, async () => {
      const sandbox = sinon.createSandbox();
      sandbox.spy(DefaultProvider.Client.Schema.prototype, 'invalidate');
      await register({
        grant_types: ['implicit'],
        response_types: ['id_token'],
        redirect_uris: ['https://localhost'],
      }).then(
        () => {
          assert(false);
        },
        () => {
          const spy = DefaultProvider.Client.Schema.prototype.invalidate;
          ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
          const call = spy.getCall(0);
          const [, code] = call.args;
          assert.deepEqual(code, 'implicit-forbid-localhost');
        },
      );
    });
  });

  describe('post_logout_redirect_uris', () => {

    defaultsTo('post_logout_redirect_uris', []);
    defaultsTo('post_logout_redirect_uris', undefined, undefined, {
      features: { rpInitiatedLogout: { enabled: false } },
    });
    mustBeArray('post_logout_redirect_uris', [{}, 'string', 123, true]);
    rejects('post_logout_redirect_uris', [123], /must only contain strings$/);

    allows('post_logout_redirect_uris', ['http://some'], {
      application_type: 'web',
    });
    allows('post_logout_redirect_uris', ['https://some'], {
      application_type: 'web',
    });
    rejects(
      'post_logout_redirect_uris',
      ['https://rp.example.com#whatever'],
      /post_logout_redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects(
      'post_logout_redirect_uris',
      ['https://rp.example.com#'],
      /post_logout_redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects('post_logout_redirect_uris', ['no-dot-reverse-notation:/some'], undefined, {
      application_type: 'web',
    });
    rejects('post_logout_redirect_uris', ['https://localhost'], undefined, {
      application_type: 'web',
      grant_types: ['implicit', 'authorization_code'],
      response_types: ['code id_token'],
    });
    allows('post_logout_redirect_uris', ['http://localhost'], {
      application_type: 'web',
    });
    rejects('post_logout_redirect_uris', ['http://some'], undefined, {
      application_type: 'native',
    });
    rejects('post_logout_redirect_uris', ['not-a-uri'], undefined, {
      application_type: 'native',
    });
    rejects('post_logout_redirect_uris', ['http://foo/bar'], undefined, {
      application_type: 'web',
      grant_types: ['implicit'],
      response_types: ['id_token'],
    });
    for (const scheme of ['javascript', 'vbscript', 'data', 'blob', 'file', 'about']) {
      rejects('post_logout_redirect_uris', [`${scheme}:foo`], `post_logout_redirect_uris must not use the ${scheme} URI scheme`, {
        application_type: 'native',
      });
    }
  });

  describe('request_object_signing_alg', () => {

    const configuration = {
      features: {
        requestObjects: { enabled: true },
        pushedAuthorizationRequests: { enabled: false },
      },
    };
    mustBeString('request_object_signing_alg', undefined, undefined, configuration);
    [
      'HS256',
      'HS384',
      'HS512',
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES384',
      'ES512',
      'Ed25519',
      'EdDSA',
      ...pqc,
    ].forEach((alg) => {
      allows('request_object_signing_alg', alg, { jwks: { keys: [sigKey] } }, configuration);
    });
    rejects('request_object_signing_alg', 'not-an-alg', undefined, undefined, configuration);
    rejects('request_object_signing_alg', 'none', undefined, undefined, configuration);
  });

  describe('require_auth_time', () => {

    defaultsTo('require_auth_time', false);
    mustBeBoolean('require_auth_time');
  });

  describe('response_types', () => {

    defaultsTo('response_types', ['code']);
    mustBeArray('response_types');
    const responseTypes = [
      'code id_token token',
      'code id_token',
      'code token',
      'code',
      'id_token token',
      'id_token',
      'none',
    ];
    responseTypes.forEach((value) => {
      const grants = [];
      if (value.includes('token')) {
        grants.push('implicit');
      }
      if (value.includes('code')) {
        grants.push('authorization_code');
      }
      allows(
        'response_types',
        [value],
        {
          grant_types: grants,
        },
        { responseTypes },
      );
    });
    allows(
      'response_types',
      responseTypes,
      {
        grant_types: ['implicit', 'authorization_code'],
      },
      { responseTypes },
    );
    allows(
      'response_types',
      ['token id_token'],
      {
        // mixed up order
        grant_types: ['implicit'],
      },
      { responseTypes },
      (client) => {
        assert.deepEqual(client.metadata().response_types, ['id_token token']);
      },
    );

    rejects('response_types', [123], /must only contain strings$/);
    allows('response_types', [], undefined, undefined, (client) => {
      ((actual) => { assert.ok('grant_types' in Object(actual)); assert.deepEqual(actual.grant_types, []); })(client.metadata());
    });
    rejects('response_types', ['not-a-type']);
    rejects('response_types', ['not-a-type', 'none']);
  });

  describe('response_modes', () => {

    defaultsTo('response_modes', undefined, undefined, undefined, (client) => {
      assert.equal(client.responseModeAllowed('query'), true);
      assert.equal(client.responseModeAllowed('fragment'), true);
      assert.equal(client.responseModeAllowed('form_post'), true);
    });
    mustBeArray('response_modes');

    allows('response_modes', ['query', 'fragment', 'form_post']);
    allows('response_modes', ['query']);
    allows('response_modes', ['fragment']);
    allows('response_modes', ['form_post']);

    allows('response_modes', ['query', 'fragment'], undefined, undefined, (client) => {
      assert.equal(client.responseModeAllowed('query'), true);
      assert.equal(client.responseModeAllowed('fragment'), true);
      assert.equal(client.responseModeAllowed('form_post'), false);
    });

    allows('response_modes', ['jwt'], undefined, { features: { jwtResponseModes: { enabled: true } } });
    allows('response_modes', ['fragment.jwt'], undefined, { features: { jwtResponseModes: { enabled: true } } });
    allows('response_modes', ['query.jwt'], undefined, { features: { jwtResponseModes: { enabled: true } } });
    allows('response_modes', ['form_post.jwt'], undefined, { features: { jwtResponseModes: { enabled: true } } });

    allows('response_modes', ['web_message'], undefined, { features: { webMessageResponseMode: { enabled: true } } });
    allows('response_modes', ['web_message.jwt'], undefined, { features: { webMessageResponseMode: { enabled: true }, jwtResponseModes: { enabled: true } } });

    rejects('response_modes', [123], /must only contain strings$/);
    rejects('response_modes', [], /must contain members$/);
    rejects('response_modes', ['not-a-mode']);
    rejects('response_modes', ['not-a-mode']);
  });

  describe('sector_identifier_uri', () => {

    mustBeString('sector_identifier_uri');
    // must be a valid sector uri => GOTO: pairwise_clients.test.js
  });

  describe('subject_type', () => {

    defaultsTo('subject_type', 'public');
    defaultsTo('subject_type', 'pairwise', undefined, { subjectTypes: ['pairwise'] });
    mustBeString('subject_type');
    allows('subject_type', 'public');
    rejects('subject_type', 'not-a-type');
  });

  {
    const configuration = {
      clientAuthMethods: [
        'none',
        'client_secret_basic',
        'client_secret_post',
        'private_key_jwt',
        'client_secret_jwt',
        'tls_client_auth',
      ],
      features: {
        mTLS: {
          enabled: true,
          selfSignedTlsClientAuth: true,
          tlsClientAuth: true,
        },
      },
    };

    describe('token_endpoint_auth_method', () => {

      defaultsTo('token_endpoint_auth_method', 'client_secret_basic', undefined, configuration);
      mustBeString('token_endpoint_auth_method', undefined, undefined, configuration);
      rejects(
        'token_endpoint_auth_method',
        'foo',
        'token_endpoint_auth_method must not be provided (no values are allowed)',
        undefined,
        {
          ...configuration,
          clientAuthMethods: [],
        },
      );

      [
        'client_secret_basic',
        'client_secret_jwt',
        'client_secret_post',
        'private_key_jwt',
        'tls_client_auth',
      ].forEach((value) => {
        switch (value) {
          case 'private_key_jwt':
            allows(
              'token_endpoint_auth_method',
              value,
              {
                jwks: { keys: [sigKey] },
              },
              configuration,
            );
            break;
          case 'tls_client_auth':
            allows(
              'token_endpoint_auth_method',
              value,
              {
                tls_client_auth_subject_dn: 'foo',
              },
              configuration,
            );
            allows(
              'token_endpoint_auth_method',
              value,
              {
                tls_client_auth_san_dns: 'foo',
              },
              configuration,
            );
            allows(
              'token_endpoint_auth_method',
              value,
              {
                tls_client_auth_san_uri: 'foo',
              },
              configuration,
            );
            allows(
              'token_endpoint_auth_method',
              value,
              {
                tls_client_auth_san_ip: 'foo',
              },
              configuration,
            );
            allows(
              'token_endpoint_auth_method',
              value,
              {
                tls_client_auth_san_email: 'foo',
              },
              configuration,
            );
            rejects(
              'token_endpoint_auth_method',
              value,
              'tls_client_auth requires one of the certificate subject value parameters',
              undefined,
              configuration,
            );
            rejects(
              'token_endpoint_auth_method',
              value,
              'only one tls_client_auth certificate subject value must be provided',
              {
                tls_client_auth_san_ip: 'foo',
                tls_client_auth_san_email: 'foo',
              },
              configuration,
            );
            break;
          default: {
            allows('token_endpoint_auth_method', value, undefined, configuration);
          }
        }
      });
      rejects('token_endpoint_auth_method', 'not-a-method', undefined, undefined, configuration);

      allows(
        'token_endpoint_auth_method',
        'none',
        {
          response_types: ['id_token'],
          grant_types: ['implicit'],
        },
        configuration,
      );
    });

    describe('token_endpoint_auth_signing_alg', () => {

      rejects('token_endpoint_auth_signing_alg', 'none');
      Object.entries({
        client_secret_jwt: ['HS', 'RS'],
        private_key_jwt: ['RS', 'HS', { jwks: { keys: [sigKey] } }],
      }).forEach(([method, [accepted, rejected, additional]]) => {
        allows(
          'token_endpoint_auth_signing_alg',
          `${accepted}256`,
          {
            token_endpoint_auth_method: method,
            ...additional,
          },
          configuration,
        );

        rejects(
          'token_endpoint_auth_signing_alg',
          `${rejected}256`,
          /^token_endpoint_auth_signing_alg must be/,
          {
            token_endpoint_auth_method: method,
            ...additional,
          },
          configuration,
        );

        rejects(
          'token_endpoint_auth_signing_alg',
          `${accepted}384`,
          /^token_endpoint_auth_signing_alg must be/,
          {
            token_endpoint_auth_method: method,
            ...additional,
          },
          {
            enabledJWA: {
              clientAuthSigningAlgValues: pull(
                cloneDeep(enabledJWA.clientAuthSigningAlgValues),
                `${accepted}384`,
              ),
            },
            ...configuration,
          },
        );
      });
    });
  }

  describe('userinfo_signed_response_alg', () => {

    const configuration = { features: { jwtUserinfo: { enabled: true } } };
    defaultsTo('userinfo_signed_response_alg', undefined, undefined, configuration);
    mustBeString('userinfo_signed_response_alg', undefined, undefined, configuration);
    allows('userinfo_signed_response_alg', 'HS256', undefined, configuration);
    rejects('userinfo_signed_response_alg', 'not-an-alg', undefined, undefined, configuration);
    rejects('userinfo_signed_response_alg', 'none', undefined, undefined, configuration);
    rejects(
      'userinfo_signed_response_alg',
      undefined,
      'userinfo_signed_response_alg is mandatory property when userinfo_encrypted_response_alg is provided',
      { userinfo_encrypted_response_alg: 'dir' },
      merge({ features: { encryption: { enabled: true } } }, configuration),
    );
  });

  describe('introspection_signed_response_alg', () => {

    const configuration = {
      features: {
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
      },
    };
    defaultsTo('introspection_signed_response_alg', 'RS256', undefined, configuration);
    mustBeString('introspection_signed_response_alg', undefined, undefined, configuration);
    allows('introspection_signed_response_alg', 'HS256', undefined, configuration);
    rejects('introspection_signed_response_alg', 'not-an-alg', undefined, undefined, configuration);
    rejects('introspection_signed_response_alg', 'none', undefined, undefined, configuration);
  });

  describe('authorization_signed_response_alg', () => {

    const configuration = { features: { jwtResponseModes: { enabled: true } } };
    defaultsTo('authorization_signed_response_alg', 'RS256', undefined, configuration);
    mustBeString('authorization_signed_response_alg', undefined, undefined, configuration);
    allows('authorization_signed_response_alg', 'HS256', undefined, configuration);
    rejects('authorization_signed_response_alg', 'not-an-alg', undefined, undefined, configuration);
    rejects('authorization_signed_response_alg', 'none', undefined, undefined, configuration);
  });

  describe('features.encryption', () => {

    const configuration = {
      features: {
        encryption: { enabled: true },
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
        jwtResponseModes: { enabled: true },
        jwtUserinfo: { enabled: true },
      },
    };

    describe('id_token_encrypted_response_alg', () => {

      defaultsTo('id_token_encrypted_response_alg', undefined);
      defaultsTo('id_token_encrypted_response_alg', undefined, undefined, configuration);
      mustBeString(
        'id_token_encrypted_response_alg',
        undefined,
        {
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      it('is required when id_token_encrypted_response_enc is also provided', { timeout: 3000 }, () => assert.rejects(
        register(
          {
            id_token_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'id_token_encrypted_response_alg is mandatory property when id_token_encrypted_response_enc is provided');
          return true;
        },
      ));
      allows('id_token_encrypted_response_alg', 'dir', undefined, configuration);
      [
        'RSA-OAEP',
        'RSA-OAEP-256',
        'RSA-OAEP-384',
        'RSA-OAEP-512',
        'ECDH-ES',
        'ECDH-ES+A128KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A256KW',
        'A128GCMKW',
        'A192GCMKW',
        'A256GCMKW',
        'A128KW',
        'A192KW',
        'A256KW',
      ].forEach((value) => {
        allows(
          'id_token_encrypted_response_alg',
          value,
          {
            jwks: { keys: [sigKey] },
          },
          configuration,
        );
      });
      rejects('id_token_encrypted_response_alg', 'not-an-alg', undefined, undefined, configuration);
      rejects('id_token_encrypted_response_alg', 'none', undefined, undefined, configuration);
    });

    describe('id_token_encrypted_response_enc', () => {

      defaultsTo('id_token_encrypted_response_enc', undefined);
      defaultsTo(
        'id_token_encrypted_response_enc',
        'A128CBC-HS256',
        {
          ['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        'id_token_encrypted_response_enc',
        undefined,
        {
          ['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            'id_token_encrypted_response_enc',
            value,
            {
              ['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            'id_token_encrypted_response_enc',
            value,
            {
              ['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        'id_token_encrypted_response_enc',
        'not-an-enc',
        undefined,
        {
          ['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    describe('userinfo_encrypted_response_alg', () => {

      const metadata = {
        jwks: { keys: [sigKey] },
        userinfo_signed_response_alg: 'RS256',
      };
      defaultsTo('userinfo_encrypted_response_alg', undefined);
      defaultsTo('userinfo_encrypted_response_alg', undefined, undefined, configuration);
      mustBeString('userinfo_encrypted_response_alg', undefined, metadata, configuration);
      it('is required when userinfo_encrypted_response_enc is also provided', { timeout: 3000 }, () => assert.rejects(
        register(
          {
            userinfo_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'userinfo_encrypted_response_alg is mandatory property when userinfo_encrypted_response_enc is provided');
          return true;
        },
      ));
      allows('userinfo_encrypted_response_alg', 'dir', metadata, configuration);
      [
        'RSA-OAEP',
        'RSA-OAEP-256',
        'RSA-OAEP-384',
        'RSA-OAEP-512',
        'ECDH-ES',
        'ECDH-ES+A128KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A256KW',
        'A128GCMKW',
        'A192GCMKW',
        'A256GCMKW',
        'A128KW',
        'A192KW',
        'A256KW',
      ].forEach((value) => {
        allows('userinfo_encrypted_response_alg', value, metadata, configuration);
      });
      rejects('userinfo_encrypted_response_alg', 'not-an-alg', undefined, undefined, configuration);
      rejects('userinfo_encrypted_response_alg', 'none', undefined, undefined, configuration);
    });

    describe('userinfo_encrypted_response_enc', () => {

      defaultsTo('userinfo_encrypted_response_enc', undefined);
      defaultsTo('userinfo_encrypted_response_enc', undefined, undefined, configuration);
      defaultsTo(
        'userinfo_encrypted_response_enc',
        'A128CBC-HS256',
        {
          ['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          ['userinfo_encrypted_response_enc'.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        'userinfo_encrypted_response_enc',
        undefined,
        {
          ['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          ['userinfo_encrypted_response_enc'.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            'userinfo_encrypted_response_enc',
            value,
            {
              ['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              ['userinfo_encrypted_response_enc'.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            'userinfo_encrypted_response_enc',
            value,
            {
              ['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'dir',
              ['userinfo_encrypted_response_enc'.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
            },
            configuration,
          );
        },
      );
      rejects(
        'userinfo_encrypted_response_enc',
        'not-an-enc',
        undefined,
        {
          ['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          ['userinfo_encrypted_response_enc'.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    describe('introspection_encrypted_response_alg', () => {

      const metadata = {
        jwks: { keys: [sigKey] },
        introspection_signed_response_alg: 'RS256',
      };
      defaultsTo('introspection_encrypted_response_alg', undefined);
      defaultsTo('introspection_encrypted_response_alg', undefined, undefined, configuration);
      mustBeString('introspection_encrypted_response_alg', undefined, metadata, configuration);
      it('is required when introspection_encrypted_response_enc is also provided', { timeout: 3000 }, () => assert.rejects(
        register(
          {
            introspection_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'introspection_encrypted_response_alg is mandatory property when introspection_encrypted_response_enc is provided');
          return true;
        },
      ));
      allows('introspection_encrypted_response_alg', 'dir', metadata, configuration);
      [
        'RSA-OAEP',
        'RSA-OAEP-256',
        'RSA-OAEP-384',
        'RSA-OAEP-512',
        'ECDH-ES',
        'ECDH-ES+A128KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A256KW',
        'A128GCMKW',
        'A192GCMKW',
        'A256GCMKW',
        'A128KW',
        'A192KW',
        'A256KW',
      ].forEach((value) => {
        allows('introspection_encrypted_response_alg', value, metadata, configuration);
      });
      rejects('introspection_encrypted_response_alg', 'not-an-alg', undefined, undefined, configuration);
      rejects('introspection_encrypted_response_alg', 'none', undefined, undefined, configuration);
    });

    describe('introspection_encrypted_response_enc', () => {

      defaultsTo('introspection_encrypted_response_enc', undefined);
      defaultsTo('introspection_encrypted_response_enc', undefined, undefined, configuration);
      defaultsTo(
        'introspection_encrypted_response_enc',
        'A128CBC-HS256',
        {
          ['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        'introspection_encrypted_response_enc',
        undefined,
        {
          ['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            'introspection_encrypted_response_enc',
            value,
            {
              ['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            'introspection_encrypted_response_enc',
            value,
            {
              ['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        'introspection_encrypted_response_enc',
        'not-an-enc',
        undefined,
        {
          ['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    describe('authorization_encrypted_response_alg', () => {

      const metadata = {
        jwks: { keys: [sigKey] },
        authorization_signed_response_alg: 'RS256',
      };
      defaultsTo('authorization_encrypted_response_alg', undefined);
      defaultsTo('authorization_encrypted_response_alg', undefined, undefined, configuration);
      mustBeString('authorization_encrypted_response_alg', undefined, metadata, configuration);
      it('is required when authorization_encrypted_response_enc is also provided', { timeout: 3000 }, () => assert.rejects(
        register(
          {
            authorization_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'authorization_encrypted_response_alg is mandatory property when authorization_encrypted_response_enc is provided');
          return true;
        },
      ));
      allows('authorization_encrypted_response_alg', 'dir', metadata, configuration);
      [
        'RSA-OAEP',
        'RSA-OAEP-256',
        'RSA-OAEP-384',
        'RSA-OAEP-512',
        'ECDH-ES',
        'ECDH-ES+A128KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A256KW',
        'A128GCMKW',
        'A192GCMKW',
        'A256GCMKW',
        'A128KW',
        'A192KW',
        'A256KW',
      ].forEach((value) => {
        allows('authorization_encrypted_response_alg', value, metadata, configuration);
      });
      rejects('authorization_encrypted_response_alg', 'not-an-alg', undefined, undefined, configuration);
      rejects('authorization_encrypted_response_alg', 'none', undefined, undefined, configuration);
    });

    describe('authorization_encrypted_response_enc', () => {

      defaultsTo('authorization_encrypted_response_enc', undefined);
      defaultsTo('authorization_encrypted_response_enc', undefined, undefined, configuration);
      defaultsTo(
        'authorization_encrypted_response_enc',
        'A128CBC-HS256',
        {
          ['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        'authorization_encrypted_response_enc',
        undefined,
        {
          ['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            'authorization_encrypted_response_enc',
            value,
            {
              ['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            'authorization_encrypted_response_enc',
            value,
            {
              ['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        'authorization_encrypted_response_enc',
        'not-an-enc',
        undefined,
        {
          ['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });
  });

  describe('features.encryption & features.request', () => {

    const configuration = {
      features: {
        encryption: { enabled: true },
        requestObjects: { enabled: true },
      },
    };
    describe('request_object_encryption_alg', () => {

      defaultsTo('request_object_encryption_alg', undefined);
      defaultsTo('request_object_encryption_alg', undefined, undefined, configuration);
      mustBeString('request_object_encryption_alg', undefined, undefined, configuration);
      it('is required when request_object_encryption_enc is also provided', { timeout: 3000 }, () => assert.rejects(
        register(
          {
            request_object_encryption_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'request_object_encryption_alg is mandatory property when request_object_encryption_enc is provided');
          return true;
        },
      ));
      allows('request_object_encryption_alg', 'dir', undefined, configuration);
      [
        'RSA-OAEP',
        'RSA-OAEP-256',
        'RSA-OAEP-384',
        'RSA-OAEP-512',
        'ECDH-ES',
        'ECDH-ES+A128KW',
        'ECDH-ES+A192KW',
        'ECDH-ES+A256KW',
        'A128GCMKW',
        'A192GCMKW',
        'A256GCMKW',
        'A128KW',
        'A192KW',
        'A256KW',
      ].forEach((value) => {
        allows('request_object_encryption_alg', value, undefined, configuration);
      });
      rejects('request_object_encryption_alg', 'not-an-alg', undefined, undefined, configuration);
      rejects('request_object_encryption_alg', 'none', undefined, undefined, configuration);
    });

    describe('request_object_encryption_enc', () => {

      defaultsTo('request_object_encryption_enc', undefined);
      defaultsTo('request_object_encryption_enc', undefined, undefined, configuration);
      defaultsTo(
        'request_object_encryption_enc',
        'A128CBC-HS256',
        {
          ['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
      mustBeString(
        'request_object_encryption_enc',
        undefined,
        {
          ['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            'request_object_encryption_enc',
            value,
            {
              ['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
            },
            configuration,
          );
          allows(
            'request_object_encryption_enc',
            value,
            {
              ['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        'request_object_encryption_enc',
        'not-an-enc',
        undefined,
        {
          ['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
    });
  });

  describe('features.pushedAuthorizationRequests', () => {

    describe('require_pushed_authorization_requests', () => {

      const configuration = (value = false) => ({
        features: {
          pushedAuthorizationRequests: {
            enabled: true,
            requirePushedAuthorizationRequests: value,
          },
        },
      });
      mustBeBoolean('require_pushed_authorization_requests', undefined, configuration());
      mustBeBoolean('require_pushed_authorization_requests', undefined, configuration(true));
      defaultsTo('require_pushed_authorization_requests', false, undefined, configuration());
      defaultsTo('require_pushed_authorization_requests', true, undefined, configuration(true));
      defaultsTo(
        'require_pushed_authorization_requests',
        true,
        {
          require_pushed_authorization_requests: false,
        },
        configuration(true),
      );
      defaultsTo('require_pushed_authorization_requests', true, undefined, {
        ...configuration(),
        clientDefaults: { require_pushed_authorization_requests: true },
      });
    });
  });

  describe('features.dpop', () => {

    describe('dpop_bound_access_tokens', () => {

      const configuration = {
        features: {
          dPoP: {
            enabled: true,
          },
        },
        responseTypes: ['code', 'code token'],
      };
      mustBeBoolean('dpop_bound_access_tokens', undefined, configuration);
      mustBeBoolean('dpop_bound_access_tokens', undefined, configuration);
      defaultsTo('dpop_bound_access_tokens', false, undefined, configuration);
      defaultsTo('dpop_bound_access_tokens', true, undefined, {
        ...configuration,
        clientDefaults: { dpop_bound_access_tokens: true },
      });
      rejects('dpop_bound_access_tokens', true, 'response_types must not include "token" when dpop_bound_access_tokens is used', { grant_types: ['authorization_code', 'implicit'], response_types: ['code', 'code token'] }, configuration);
    });
  });

  describe('features.ciba', () => {

    const configuration = {
      features: {
        ciba: { enabled: true, deliveryModes: ['ping', 'poll'] },
      },
    };
    const metadata = {
      grant_types: ['urn:openid:params:grant-type:ciba'],
      redirect_uris: [],
      response_types: [],
      backchannel_token_delivery_mode: 'poll',
    };

    describe('backchannel_user_code_parameter', () => {

      mustBeBoolean('backchannel_user_code_parameter', undefined, configuration);
      defaultsTo('backchannel_user_code_parameter', false, undefined, configuration);
    });

    describe('backchannel_token_delivery_mode', () => {

      mustBeString('backchannel_token_delivery_mode', undefined, undefined, configuration);
      isRequired('backchannel_token_delivery_mode', undefined, configuration, {
        ...metadata,
        backchannel_token_delivery_mode: undefined,
      });
    });

    describe('backchannel_client_notification_endpoint', () => {

      isRequired('backchannel_client_notification_endpoint', undefined, configuration, {
        ...metadata,
        backchannel_token_delivery_mode: 'ping',
      });
      mustBeUri('backchannel_client_notification_endpoint', ['https'], configuration, {
        ...metadata,
        backchannel_token_delivery_mode: 'ping',
      });
    });

    describe('backchannel_authentication_request_signing_alg', () => {

      const withRequestObjects = merge({}, configuration, {
        features: { requestObjects: { enabled: true } },
      });
      mustBeString('backchannel_authentication_request_signing_alg', undefined, metadata, withRequestObjects);
      [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'ES256',
        'ES384',
        'ES512',
        'Ed25519',
        'EdDSA',
        ...pqc,
      ].forEach((alg) => {
        allows('backchannel_authentication_request_signing_alg', alg, { ...metadata, jwks: { keys: [sigKey] } }, withRequestObjects);
      });
      rejects('backchannel_authentication_request_signing_alg', 'not-an-alg', undefined, metadata, withRequestObjects);
      rejects('backchannel_authentication_request_signing_alg', 'none', undefined, metadata, withRequestObjects);
      rejects('backchannel_authentication_request_signing_alg', 'none', undefined, metadata, withRequestObjects);
      rejects('backchannel_authentication_request_signing_alg', 'HS256', undefined, metadata, withRequestObjects);
      rejects('backchannel_authentication_request_signing_alg', 'HS384', undefined, metadata, withRequestObjects);
      rejects('backchannel_authentication_request_signing_alg', 'HS512', undefined, metadata, withRequestObjects);
      defaultsTo('backchannel_authentication_request_signing_alg', undefined, undefined, withRequestObjects);
    });

    allows(
      'subject_type',
      'pairwise',
      {
        ...metadata,
        token_endpoint_auth_method: 'private_key_jwt',
        subject_type: 'pairwise',
        jwks_uri: 'https://rp.example.com/jwks',
      },
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      (client) => {
        assert.deepEqual(sectorIdentifier(client), 'rp.example.com');
      },
    );
    isRequired(
      'jwks_uri',
      [undefined],
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      { ...metadata, subject_type: 'pairwise' },
    );
    isRequired(
      'sector_identifier_uri',
      [undefined],
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      {
        ...metadata,
        jwks_uri: 'https://rp.example.com/sector',
        subject_type: 'pairwise',
        response_types: ['code'],
        grant_types: [...metadata.grant_types, 'authorization_code'],
        redirect_uris: ['https://rp.example.com/cb'],
      },
    );
    rejects(
      'subject_type',
      'pairwise',
      'pairwise urn:openid:params:grant-type:ciba clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods',
      { ...metadata, subject_type: 'pairwise', jwks_uri: 'https://rp.example.com/jwks' },
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
    );
  });

  describe('features.deviceFlow', () => {
    const configuration = { features: { deviceFlow: { enabled: true } } };
    const metadata = {
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
      response_types: [],
      redirect_uris: undefined,
    };

    defaultsTo('redirect_uris', [], metadata, configuration);
    defaultsTo('redirect_uris', ['https://rp.example.com/callback'], metadata, {
      ...configuration,
      clientDefaults: { redirect_uris: ['https://rp.example.com/callback'] },
    });
    rejects('redirect_uris', null, 'redirect_uris must be an array', metadata, configuration);
    allows(
      'subject_type',
      'pairwise',
      {
        ...metadata,
        token_endpoint_auth_method: 'private_key_jwt',
        subject_type: 'pairwise',
        jwks_uri: 'https://rp.example.com/jwks',
      },
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      (client) => {
        assert.deepEqual(sectorIdentifier(client), 'rp.example.com');
      },
    );
    isRequired(
      'jwks_uri',
      [undefined],
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      { ...metadata, subject_type: 'pairwise' },
    );
    isRequired(
      'sector_identifier_uri',
      [undefined],
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
      {
        ...metadata,
        jwks_uri: 'https://rp.example.com/sector',
        subject_type: 'pairwise',
        response_types: ['code'],
        grant_types: [...metadata.grant_types, 'authorization_code'],
        redirect_uris: ['https://rp.example.com/cb'],
      },
    );
    rejects(
      'subject_type',
      'pairwise',
      'pairwise urn:ietf:params:oauth:grant-type:device_code clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods',
      { ...metadata, subject_type: 'pairwise', jwks_uri: 'https://rp.example.com/jwks' },
      { ...configuration, subjectTypes: ['pairwise', 'public'] },
    );
  });

  describe('features.clientCredentials', () => {
    const configuration = { features: { clientCredentials: { enabled: true } } };
    const metadata = {
      grant_types: ['client_credentials'],
      response_types: [],
      redirect_uris: undefined,
    };

    defaultsTo('redirect_uris', [], metadata, configuration);
    defaultsTo('redirect_uris', ['https://rp.example.com/callback'], metadata, {
      ...configuration,
      clientDefaults: { redirect_uris: ['https://rp.example.com/callback'] },
    });
    rejects('redirect_uris', null, 'redirect_uris must be an array', metadata, configuration);
  });

  describe('jwks', () => {

    const configuration = {
      features: {
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
        revocation: { enabled: true },
        encryption: { enabled: true },
        jwtUserinfo: { enabled: true },
        ciba: { enabled: true },
        requestObjects: { enabled: true },
      },
    };

    [false, Boolean, 'foo', 123, null, { kty: null }, { kty: '' }].forEach((value) => {
      rejects('jwks', { keys: [value] }, 'client JSON Web Key Set is invalid');
    });
    rejects('jwks', 'string', 'client JSON Web Key Set is invalid');
    rejects('jwks', null, 'client JSON Web Key Set is invalid');
    rejects('jwks', {}, 'client JSON Web Key Set is invalid');
    rejects('jwks', 1, 'client JSON Web Key Set is invalid');
    rejects('jwks', 0, 'client JSON Web Key Set is invalid');
    rejects('jwks', true, 'client JSON Web Key Set is invalid');
    rejects('jwks', { keys: [privateKey] }, 'client JSON Web Key Set is invalid');
    rejects(
      'jwks',
      { keys: [{ k: '6vl9Rlk88HO8onFHq0ZvTtga68vkUr-bRZ2Hvxu-rAw', kty: 'oct' }] },
      'client JSON Web Key Set is invalid',
    );
    rejects(
      'jwks',
      { keys: [{ kty: 'oct', kid: 'jf1nb1YotqxK9viWsXMsngnTCmO2r3w_moVIPtaf8wU' }] },
      'client JSON Web Key Set is invalid',
    );
    allows('jwks', { keys: [{ kty: 'unrecognized' }] });
    allows('jwks', { keys: [] });

    it('provides specific details for invalid JWK members', { timeout: 3000 }, async () => {
      const invalid = [
        [[{ kty: 'unrecognized' }, {}], 'jwks.keys[1].kty must be a non-empty string'],
        [[{ kty: 'EC' }], 'jwks.keys[0].crv must be a non-empty string for EC keys'],
        [[{ kty: 'EC', crv: 'P-256' }], 'jwks.keys[0].x must be a non-empty string for EC keys'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x' }], 'jwks.keys[0].y must be a non-empty string for EC keys'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' }], 'jwks.keys[0].d must not be provided for EC keys'],
        [[{ kty: 'OKP' }], 'jwks.keys[0].crv must be a non-empty string for OKP keys'],
        [[{ kty: 'OKP', crv: 'Ed25519' }], 'jwks.keys[0].x must be a non-empty string for OKP keys'],
        [[{ kty: 'OKP', crv: 'Ed25519', x: 'x', d: 'd' }], 'jwks.keys[0].d must not be provided for OKP keys'],
        [[{ kty: 'AKP' }], 'jwks.keys[0].alg must be a non-empty string for AKP keys'],
        [[{ kty: 'AKP', alg: 'ML-DSA-44' }], 'jwks.keys[0].pub must be a non-empty string for AKP keys'],
        [[{ kty: 'AKP', alg: 'ML-DSA-44', pub: 'pub', priv: 'priv' }], 'jwks.keys[0].priv must not be provided for AKP keys'],
        [[{ kty: 'RSA' }], 'jwks.keys[0].e must be a non-empty string for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB' }], 'jwks.keys[0].n must be a non-empty string for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', d: 'd', p: 'p' }], 'jwks.keys[0].d must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', p: 'p' }], 'jwks.keys[0].p must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', q: 'q' }], 'jwks.keys[0].q must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', dp: 'dp' }], 'jwks.keys[0].dp must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', dq: 'dq' }], 'jwks.keys[0].dq must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', qi: 'qi' }], 'jwks.keys[0].qi must not be provided for RSA keys'],
        [[{ kty: 'RSA', e: 'AQAB', n: 'n', oth: [] }], 'jwks.keys[0].oth must not be provided for RSA keys'],
        [[{ kty: 'oct' }], 'jwks.keys[0] must not contain symmetric keys'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 1 }], 'jwks.keys[0].alg must be a non-empty string if provided'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: '' }], 'jwks.keys[0].kid must be a non-empty string if provided'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', use: true }], 'jwks.keys[0].use must be a non-empty string if provided'],
        [[{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', x5c: [1] }], 'jwks.keys[0].x5c must be an array of non-empty strings if provided'],
      ];

      for (const [invalidKeys, detail] of invalid) {
        await assert.rejects(register({ jwks: { keys: invalidKeys } }), (err) => {
          assert.ok(err instanceof errors.InvalidClientMetadata);
          assert.equal(err.error_description, 'client JSON Web Key Set is invalid');
          assert.equal(err.error_detail, detail);
          ((actual) => { assert.ok(actual instanceof Error); assert.ok('message' in Object(actual)); assert.equal(actual.message, detail); })(err.cause);
          assert.equal(err.cause.cause, invalidKeys.at(-1));
          return true;
        });
      }
    });

    rejects(
      'jwks',
      undefined,
      'jwks or jwks_uri is mandatory for this client',
      {
        token_endpoint_auth_method: 'private_key_jwt',
      },
      configuration,
    );

    for (const prop of [
      'request_object_signing_alg',
      'backchannel_authentication_request_signing_alg',
    ]) {
      for (const alg of ['RS256', 'PS384', 'ES512', 'Ed25519', 'EdDSA', ...pqc]) {
        rejects(
          'jwks',
          undefined,
          'jwks or jwks_uri is mandatory for this client',
          {
            [prop]: alg,
          },
          configuration,
        );
      }
    }

    [
      'id_token_encrypted_response_alg',
      'userinfo_encrypted_response_alg',
      'introspection_encrypted_response_alg',
    ].forEach((prop) => {
      ['RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'].forEach(
        (alg) => {
          rejects(
            'jwks',
            undefined,
            'jwks or jwks_uri is mandatory for this client',
            {
              [prop]: alg,
              [prop.replace('encrypted', 'signed')]: 'RS256',
            },
            configuration,
          );
        },
      );
    });
  });

  describe('features.mTLS.certificateBoundAccessTokens', () => {

    describe('tls_client_certificate_bound_access_tokens', () => {

      const configuration = {
        features: {
          mTLS: { enabled: true, certificateBoundAccessTokens: true },
        },
        responseTypes: ['code', 'code token'],
      };

      defaultsTo('tls_client_certificate_bound_access_tokens', false, undefined, configuration);
      defaultsTo('tls_client_certificate_bound_access_tokens', undefined);
      mustBeBoolean('tls_client_certificate_bound_access_tokens', undefined, configuration);
      rejects('tls_client_certificate_bound_access_tokens', true, 'response_types must not include "token" when tls_client_certificate_bound_access_tokens is used', { grant_types: ['authorization_code', 'implicit'], response_types: ['code', 'code token'] }, configuration);
    });
  });

  describe('features.backchannelLogout', () => {

    const configuration = {
      features: {
        backchannelLogout: { enabled: true },
      },
    };

    describe('backchannel_logout_uri', () => {

      defaultsTo('backchannel_logout_uri', undefined);
      mustBeString('backchannel_logout_uri', undefined, undefined, configuration);
      mustBeUri('backchannel_logout_uri', ['http', 'https'], configuration);
    });

    describe('backchannel_logout_session_required', () => {

      defaultsTo('backchannel_logout_session_required', undefined);
      defaultsTo('backchannel_logout_session_required', false, undefined, configuration);
      mustBeBoolean('backchannel_logout_session_required', undefined, configuration);
    });
  });

  {
    const configuration = {
      features: {
        mTLS: { enabled: true, tlsClientAuth: true },
        revocation: { enabled: true },
        introspection: { enabled: true },
      },
      clientAuthMethods: ['tls_client_auth', 'client_secret_basic'],
    };

    describe('tls_client_auth_subject_dn', () => {

      mustBeString('tls_client_auth_subject_dn', undefined, undefined, configuration);
      allows(
        'tls_client_auth_subject_dn',
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows('tls_client_auth_subject_dn', 'foo', undefined, configuration, (client) => {
        assert.deepEqual(client.metadata().tls_client_auth_subject_dn, undefined);
      });
    });

    describe('tls_client_auth_san_dns', () => {

      mustBeString('tls_client_auth_san_dns', undefined, undefined, configuration);
      allows(
        'tls_client_auth_san_dns',
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows('tls_client_auth_san_dns', 'foo', undefined, configuration, (client) => {
        assert.deepEqual(client.metadata().tls_client_auth_san_dns, undefined);
      });
    });

    describe('tls_client_auth_san_uri', () => {

      mustBeString('tls_client_auth_san_uri', undefined, undefined, configuration);
      allows(
        'tls_client_auth_san_uri',
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows('tls_client_auth_san_uri', 'foo', undefined, configuration, (client) => {
        assert.deepEqual(client.metadata().tls_client_auth_san_uri, undefined);
      });
    });

    describe('tls_client_auth_san_ip', () => {

      mustBeString('tls_client_auth_san_ip', undefined, undefined, configuration);
      allows(
        'tls_client_auth_san_ip',
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows('tls_client_auth_san_ip', 'foo', undefined, configuration, (client) => {
        assert.deepEqual(client.metadata().tls_client_auth_san_ip, undefined);
      });
    });

    describe('tls_client_auth_san_email', () => {

      mustBeString('tls_client_auth_san_email', undefined, undefined, configuration);
      allows(
        'tls_client_auth_san_email',
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows('tls_client_auth_san_email', 'foo', undefined, configuration, (client) => {
        assert.deepEqual(client.metadata().tls_client_auth_san_email, undefined);
      });
    });
  }

  describe('jwks_uri', () => {

    mustBeString('jwks_uri');

    // more in client_keystore.test.js
  });

  it('allows unrecognized properties but does not yield them back', { timeout: 3000 }, () => register({
    unrecognized: true,
  }).then((client) => {
    assert.ok(!('unrecognized' in Object(client)));
  }));

  it('allows clients without grants, for introspection, revocation (RS clients)', { timeout: 3000 }, () => register({
    client_id: 'authorization-server',
    client_secret: 'foobar',
    redirect_uris: [],
    response_types: [],
    grant_types: [],
  }).then((client) => {
    assert.equal(client.grantTypes.length, 0);
    assert.equal(client.responseTypes.length, 0);
    assert.equal(client.redirectUris.length, 0);
  }));

  it('allows clients only with client_credentials', { timeout: 3000 }, () => register(
    {
      client_id: 'resource-server',
      client_secret: 'foobar',
      redirect_uris: [],
      response_types: [],
      grant_types: ['client_credentials'],
    },
    {
      features: { clientCredentials: { enabled: true } },
    },
  ).then((client) => {
    assert.notEqual(client.grantTypes.length, 0);
    assert.equal(client.responseTypes.length, 0);
    assert.equal(client.redirectUris.length, 0);
  }));

  describe('authorization_details_types', () => {

    const features = {
      richAuthorizationRequests: {
        enabled: true,
        types: {
          foo: {
            validate() {},
          },
        },
      },
    };
    mustBeArray('authorization_details_types', undefined, { features });
    defaultsTo('authorization_details_types', [], undefined, { features });
    rejects('authorization_details_types', [123], /must only contain strings$/, undefined, { features });
    rejects('authorization_details_types', ['bar'], /can only contain 'foo'$/, undefined, { features });
  });

  it('fails to determine sector identifier', { timeout: 3000 }, () => register(
    {
      client_id: 'authorization-server',
      client_secret: 'foobar',
      redirect_uris: [],
      response_types: [],
      grant_types: [],
      subject_type: 'pairwise',
    },
    { subjectTypes: ['pairwise', 'public'] },
  ).then((client) => {
    assert.equal(client.grantTypes.length, 0);
    assert.equal(client.responseTypes.length, 0);
    assert.equal(client.redirectUris.length, 0);
    assert.throws(() => sectorIdentifier(client));
    try {
      sectorIdentifier(client);
    } catch (err) {
      assert.deepEqual(err.error, 'invalid_client_metadata');
      assert.deepEqual(err.error_description, 'could not determine a sector identifier');
    }
  }));

  describe(
    'clientDefaults configuration option allows for default client metadata to be changed',
    () => {
      defaultsTo('token_endpoint_auth_method', 'client_secret_post', undefined, {
        clientDefaults: {
          token_endpoint_auth_method: 'client_secret_post',
        },
      });
      defaultsTo('id_token_signed_response_alg', 'PS256', undefined, {
        clientDefaults: {
          id_token_signed_response_alg: 'PS256',
        },
      });
      defaultsTo('grant_types', ['authorization_code', 'refresh_token'], undefined, {
        clientDefaults: {
          grant_types: ['authorization_code', 'refresh_token'],
        },
      });
      defaultsTo('response_types', ['code id_token'], undefined, {
        clientDefaults: {
          response_types: ['code id_token'],
          grant_types: ['authorization_code', 'implicit'],
        },
      });
    },
  );

  describe('OpenID Connect Relying Party Metadata Choices 1.0', () => {

    const configuration = {
      features: {
        rpMetadataChoices: {
          enabled: true,
        },
      },
    };

    describe('id_token_signing_alg_values_supported', () => {

      defaultsTo('id_token_signing_alg_values_supported', undefined);
      defaultsTo('id_token_signing_alg_values_supported', undefined, undefined, configuration);
      mustBeArray('id_token_signing_alg_values_supported', undefined, configuration);
      // picks an explicit value if it's in the choice list
      const supported = ['PS256', 'ES256', 'RS256'];
      for (const alg of supported) {
        defaultsTo('id_token_signed_response_alg', alg, {
          id_token_signed_response_alg: alg,
          id_token_signing_alg_values_supported: ['PS256', 'RS256', 'ES256'],
        }, configuration);
      }
      // rejects a choice if it includes non-string values
      rejects('id_token_signing_alg_values_supported', [0], `${'id_token_signing_alg_values_supported'} must only contain strings`, undefined, configuration);
      // rejects a choice if an explicit value is not in it
      rejects('id_token_signing_alg_values_supported', ['ES256'], `${'id_token_signing_alg_values_supported'} must include the value of provided id_token_signed_response_alg`, {
        id_token_signed_response_alg: 'RS256',
      }, configuration);
      // rejects a choice if there are no supported values in it
      rejects('id_token_signing_alg_values_supported', ['ES256'], `${'id_token_signing_alg_values_supported'} includes no supported values`, undefined, {
        ...configuration,
        enabledJWA: {
          idTokenSigningAlgValues: ['RS256'],
        },
      });
    });
  });
});
