import { strict as assert } from 'node:assert';
import * as util from 'node:util';

import sinon from 'sinon';
import { expect } from 'chai';
import merge from 'lodash/merge.js';
import omit from 'lodash/omit.js';
import pull from 'lodash/pull.js';
import cloneDeep from 'lodash/cloneDeep.js';

import Provider, { errors } from '../../lib/index.js';
import { enabledJWA } from '../default.config.js';
import sectorIdentifier from '../../lib/helpers/sector_identifier.js';
import keys, { stripPrivateJWKFields } from '../keys.js';

const sigKey = stripPrivateJWKFields(keys[0]);
const privateKey = keys[0];
const { InvalidClientMetadata } = errors;

describe('Client metadata validation', () => {
  let DefaultProvider;
  before(() => {
    DefaultProvider = new Provider('http://localhost', {
      jwks: { keys },
      enabledJWA: cloneDeep(enabledJWA),
    });
  });

  function addClient(metadata, configuration) {
    let provider;
    if (configuration) {
      provider = new Provider(
        'http://localhost',
        merge(
          {
            jwks: { keys },
            enabledJWA: cloneDeep(enabledJWA),
          },
          configuration,
        ),
      );
    } else {
      provider = DefaultProvider;
    }

    return i(provider).clientAdd({
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
      ...metadata,
    });
  }

  const mustBeString = (
    prop,
    values = [[], 123, true, null, false, {}, ''], // eslint-disable-line default-param-last
    metadata,
    configuration,
  ) => {
    values.forEach((value) => {
      let msg = util.format('must be a string, %j provided', value);
      if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      // eslint-disable-next-line max-len
      it(msg, () => assert.rejects(addClient({ ...metadata, [prop]: value }, configuration), (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        expect(err.error_description).to.equal(`${prop} must be a non-empty string if provided`);
        return true;
      }));
    });
  };

  const mustBeUri = (prop, protocols, configuration, metadata) => {
    it('must be a uri', () => assert.rejects(
      addClient(
        {
          ...metadata,
          [prop]: 'whatever://not but not a uri',
        },
        configuration,
      ),
      (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        if (protocols.length === 1 && protocols[0] === 'https') {
          expect(err.error_description).to.equal(`${prop} must be a https uri`);
        } else {
          expect(err.error_description).to.equal(`${prop} must be a web uri`);
        }
        return true;
      },
    ));

    protocols.forEach((protocol) => {
      it(`can be ${protocol} uri`, () => addClient({
        [prop]: `${protocol}://example.com/${prop}`,
      }));
    });
  };

  // eslint-disable-next-line default-param-last
  const mustBeArray = (prop, values = [{}, 'string', 123, true, null, false], configuration) => {
    values.forEach((value) => {
      let msg = util.format('must be a array, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => assert.rejects(
        addClient(
          {
            [prop]: value,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            expect(err.message).to.equal('invalid_redirect_uri');
          } else {
            expect(err.message).to.equal('invalid_client_metadata');
          }
          expect(err.error_description).to.equal(`${prop} must be an array`);
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
      it(msg, () => assert.rejects(
        addClient(
          {
            [prop]: value,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            expect(err.message).to.equal('invalid_redirect_uri');
          } else {
            expect(err.message).to.equal('invalid_client_metadata');
          }
          expect(err.error_description).to.equal(`${prop} must be a boolean`);
          return true;
        },
      ));
    });
  };

  const defaultsTo = (prop, value, metadata, configuration) => {
    let msg = util.format('defaults to %s', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);

    it(msg, () => addClient(metadata, configuration).then((client) => {
      if (value === undefined) {
        expect(client.metadata()).not.to.have.property(prop);
      } else {
        expect(client.metadata()).to.have.property(prop).and.eql(value);
      }
    }));
  };

  const isRequired = (prop, values, configuration, metadata) => {
    (values || [null, undefined, '']).forEach((value) => {
      let msg = util.format('is required, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => assert.rejects(
        addClient(
          {
            [prop]: value,
            ...metadata,
          },
          configuration,
        ),
        (err) => {
          if (prop === 'redirect_uris') {
            expect(err.message).to.equal('invalid_redirect_uri');
          } else {
            expect(err.message).to.equal('invalid_client_metadata');
          }
          expect(err.error_description).to.equal(`${prop} is mandatory property`);
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
      expect(client.metadata()[prop]).to.eql(value);
    },
  ) => {
    let msg = util.format('passes %j', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    // eslint-disable-next-line max-len
    it(msg, () => addClient({ ...metadata, [prop]: value }, configuration).then(assertion, (err) => {
      if (err instanceof InvalidClientMetadata) {
        throw new Error(`InvalidClientMetadata received ${err.message} ${err.error_description}`);
      }
    }));
  };

  const rejects = (prop, value, description, metadata, configuration) => {
    let msg = util.format('rejects %j', value);
    if (metadata) msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    // eslint-disable-next-line max-len
    it(msg, () => assert.rejects(addClient({ ...metadata, [prop]: value }, configuration), (err) => {
      if (prop === 'redirect_uris') {
        expect(err.message).to.equal('invalid_redirect_uri');
      } else {
        expect(err.message).to.equal('invalid_client_metadata');
      }
      if (description) {
        expect(err.error_description).to[description.exec ? 'match' : 'equal'](description);
      }
      return true;
    }));
  };

  context('application_type', function () {
    defaultsTo(this.title, 'web');
    mustBeString(this.title);

    allows(this.title, 'web');
    allows(this.title, 'native', {
      redirect_uris: ['com.example.myapp:/localhost/redirect'],
    });
    rejects(this.title, 'foobar', "application_type must be 'native' or 'web'");
  });

  context('client_id', function () {
    isRequired(this.title);
    mustBeString(this.title, [123, {}, [], true]);

    allows(this.title, 'whatever client id');
    rejects(this.title, '£', 'invalid client_id value');
  });

  context('client_name', function () {
    mustBeString(this.title);
    allows(this.title, 'whatever client name');
  });

  context('client_secret', function () {
    isRequired(this.title);
    mustBeString(this.title, [123, {}, [], true]);
    allows(this.title, 'whatever client secret');
    rejects(this.title, '£', 'invalid client_secret value');
    // must of certain length => GOTO: client_secrets.test.js
  });

  context('contacts', function () {
    mustBeArray(this.title);
    allows(this.title, ['developer@example.com', 'info@example.com', 'info+some@example.com']);
    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, ['john doe'], 'contacts can only contain email addresses');
  });

  context('default_acr_values', function () {
    mustBeArray(this.title);
    const acrValues = ['0', '1', '2'];

    allows(this.title, []);
    acrValues.forEach((value) => {
      allows(this.title, [value], undefined, { acrValues });
    });
    allows(this.title, acrValues, undefined, { acrValues });
    rejects(this.title, [123], /must only contain strings$/);
    rejects(
      this.title,
      ['not a member'],
      'default_acr_values must be empty (no values are allowed)',
    );
    rejects(this.title, [
      'not a member',
      '1',
      'default_acr_values must be empty (no values are allowed)',
    ]);
    rejects(
      this.title,
      ['not a member'],
      "default_acr_values can only contain '0', '1', or '2'",
      undefined,
      { acrValues },
    );
    rejects(
      this.title,
      ['not a member', '1'],
      "default_acr_values can only contain '0', '1', or '2'",
      undefined,
      { acrValues },
    );
  });

  context('require_signed_request_object', function () {
    const configuration = (value = false, requestUri = true) => ({
      features: {
        requestObjects: {
          requestUri,
          requireSignedRequestObject: value,
        },
        pushedAuthorizationRequests: {
          enabled: false,
        },
      },
    });
    mustBeBoolean(this.title, undefined, configuration());
    defaultsTo(this.title, undefined, undefined, configuration(false, false));
    defaultsTo(this.title, false, undefined, configuration());
    defaultsTo(this.title, true, undefined, configuration(true));
    defaultsTo(
      this.title,
      true,
      {
        require_signed_request_object: false,
      },
      configuration(true),
    );
    defaultsTo(this.title, true, undefined, {
      ...configuration(),
      clientDefaults: { require_signed_request_object: true },
    });
  });

  context('default_max_age', function () {
    allows(this.title, 5);
    allows(this.title, 0);
    rejects(this.title, Number.MAX_SAFE_INTEGER + 1);
    rejects(this.title, -1);
    rejects(this.title, true);
    rejects(this.title, 'string');
    rejects(this.title, {});
    rejects(this.title, []);
  });

  context('grant_types', function () {
    defaultsTo(this.title, ['authorization_code']);
    mustBeArray(this.title);
    allows(this.title, ['authorization_code', 'refresh_token']);
    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, []);
    rejects(this.title, ['not-a-type']);
    rejects(this.title, ['implicit'], undefined, {
      // misses authorization_code
      response_types: ['id_token', 'code'],
    });
    rejects(this.title, ['authorization_code'], undefined, {
      // misses implicit
      response_types: ['id_token'],
    });
    rejects(this.title, ['authorization_code'], undefined, {
      // misses implicit
      response_types: ['token'],
    });
  });

  context('id_token_signed_response_alg', function () {
    defaultsTo(this.title, 'RS256');
    mustBeString(this.title);
    rejects(this.title, 'none', undefined, {
      response_types: ['code id_token'],
    });
    rejects(this.title, 'none');
  });

  ['client_uri', 'logo_uri', 'policy_uri', 'tos_uri'].forEach((prop) => {
    context(prop, function () {
      mustBeString(this.title);
      mustBeUri(this.title, ['http', 'https']);
    });
  });

  context('initiate_login_uri', function () {
    mustBeString(this.title);
    mustBeUri(this.title, ['https']);
  });

  context('scope', function () {
    mustBeString(this.title);
    allows(this.title, undefined);
    allows(this.title, 'openid');
    allows(this.title, 'offline_access');
    allows(this.title, 'openid offline_access');
    allows(this.title, 'openid profile', undefined, { scopes: ['profile'] });
    allows(this.title, 'openid profile', undefined, { claims: { profile: ['given_name'] } });
    allows(this.title, 'profile', undefined, { scopes: ['profile'] });
    allows(this.title, 'profile', undefined, { claims: { profile: ['given_name'] } });
    rejects(
      this.title,
      'foo',
      'scope must only contain Authorization Server supported scope values',
    );
  });

  context('redirect_uris', function () {
    isRequired(this.title);
    mustBeArray(this.title, [{}, 'string', 123, true]);
    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, [], /must contain members$/);

    allows(this.title, ['http://some'], {
      application_type: 'web',
    });
    allows(this.title, ['https://some'], {
      application_type: 'web',
    });
    rejects(this.title, ['https://rp.example.com#'], /redirect_uris must not contain fragments$/);
    rejects(
      this.title,
      ['https://rp.example.com#whatever'],
      /redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects(this.title, ['no-dot-reverse-notation:/some'], undefined, {
      application_type: 'web',
    });
    rejects(this.title, ['https://localhost'], undefined, {
      application_type: 'web',
      grant_types: ['implicit', 'authorization_code'],
      response_types: ['code id_token'],
    });
    allows(this.title, ['http://localhost'], {
      application_type: 'web',
    });
    rejects(this.title, ['http://some'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['not-a-uri'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['http://foo/bar'], undefined, {
      application_type: 'web',
      grant_types: ['implicit'],
      response_types: ['id_token'],
    });
    it('has an schema invalidation hook for forcing https on implicit', async () => {
      const sandbox = sinon.createSandbox();
      sandbox.spy(DefaultProvider.Client.Schema.prototype, 'invalidate');
      await addClient({
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
            expect(spy).to.have.property('calledOnce', true);
            const call = spy.getCall(0);
            const [, code] = call.args;
            expect(code).to.eql('implicit-force-https');
          },
        )
        .finally(() => {
          sandbox.restore();
        });
    });
    it('has an schema invalidation hook for preventing localhost', async () => {
      const sandbox = sinon.createSandbox();
      sandbox.spy(DefaultProvider.Client.Schema.prototype, 'invalidate');
      await addClient({
        grant_types: ['implicit'],
        response_types: ['id_token'],
        redirect_uris: ['https://localhost'],
      }).then(
        () => {
          assert(false);
        },
        () => {
          const spy = DefaultProvider.Client.Schema.prototype.invalidate;
          expect(spy).to.have.property('calledOnce', true);
          const call = spy.getCall(0);
          const [, code] = call.args;
          expect(code).to.eql('implicit-forbid-localhost');
        },
      );
    });
  });

  context('post_logout_redirect_uris', function () {
    defaultsTo(this.title, []);
    defaultsTo(this.title, undefined, undefined, {
      features: { rpInitiatedLogout: { enabled: false } },
    });
    mustBeArray(this.title, [{}, 'string', 123, true]);
    rejects(this.title, [123], /must only contain strings$/);

    allows(this.title, ['http://some'], {
      application_type: 'web',
    });
    allows(this.title, ['https://some'], {
      application_type: 'web',
    });
    rejects(
      this.title,
      ['https://rp.example.com#'],
      /post_logout_redirect_uris must not contain fragments$/,
    );
    rejects(
      this.title,
      ['https://rp.example.com#whatever'],
      /post_logout_redirect_uris must not contain fragments$/,
      {
        application_type: 'web',
      },
    );
    rejects(this.title, ['no-dot-reverse-notation:/some'], undefined, {
      application_type: 'web',
    });
    rejects(this.title, ['https://localhost'], undefined, {
      application_type: 'web',
      grant_types: ['implicit', 'authorization_code'],
      response_types: ['code id_token'],
    });
    allows(this.title, ['http://localhost'], {
      application_type: 'web',
    });
    rejects(this.title, ['http://some'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['not-a-uri'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['http://foo/bar'], undefined, {
      application_type: 'web',
      grant_types: ['implicit'],
      response_types: ['id_token'],
    });
  });

  context('request_object_signing_alg', function () {
    for (const configuration of [
      {
        features: {
          requestObjects: { requestUri: true, request: false },
          pushedAuthorizationRequests: { enabled: false },
        },
      },
      {
        features: {
          requestObjects: { requestUri: false, request: true },
          pushedAuthorizationRequests: { enabled: false },
        },
      },
    ]) {
      mustBeString(this.title, undefined, undefined, configuration);
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
        'EdDSA',
      ].forEach((alg) => {
        allows(this.title, alg, { jwks: { keys: [sigKey] } }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    }
  });

  context('request_uris', function () {
    defaultsTo(this.title, [], undefined, {
      features: {
        requestObjects: { requestUri: true },
      },
    });
    defaultsTo(this.title, undefined, undefined, {
      features: {
        requestObjects: {
          requestUri: true,
          requireUriRegistration: false,
        },
      },
    });
    const configuration = {
      features: {
        requestObjects: { requestUri: true },
      },
    };
    mustBeArray(this.title, undefined, configuration);

    allows(this.title, ['https://a-web-uri'], undefined, configuration);
    allows(this.title, ['http://a-web-uri'], /must only contain https uris$/, configuration);
    rejects(this.title, [123], /must only contain strings$/, undefined, configuration);
    rejects(
      this.title,
      ['not a uri'],
      /request_uris must only contain web uris$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['custom-scheme://not-a-web-uri'],
      /request_uris must only contain web uris$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['urn:example'],
      /request_uris must only contain web uris$/,
      undefined,
      configuration,
    );
  });

  context('web_message_uris', function () {
    const configuration = { features: { webMessageResponseMode: { enabled: true } } };
    defaultsTo(this.title, [], undefined, configuration);
    mustBeArray(this.title, undefined, configuration);

    allows(this.title, [], undefined, configuration);
    allows(this.title, ['https://example.com'], undefined, configuration);
    allows(this.title, ['https://example.com:3000'], undefined, configuration);
    rejects(this.title, [123], /must only contain strings$/, undefined, configuration);
    rejects(this.title, [true], /must only contain strings$/, undefined, configuration);
    rejects(this.title, [null], /must only contain strings$/, undefined, configuration);
    rejects(this.title, ['not a uri'], /must only contain valid uris$/, undefined, configuration);
    rejects(
      this.title,
      ['custom-scheme://not-a-web-uri'],
      /must only contain web uris$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['https://example.com/'],
      /must only contain origins$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['https://example.com?'],
      /must only contain origins$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['https://example.com#'],
      /must only contain origins$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['https://foo:bar@example.com'],
      /must only contain origins$/,
      undefined,
      configuration,
    );
    rejects(
      this.title,
      ['https://foo@example.com'],
      /must only contain origins$/,
      undefined,
      configuration,
    );
  });

  context('require_auth_time', function () {
    defaultsTo(this.title, false);
    mustBeBoolean(this.title);
  });

  context('response_types', function () {
    defaultsTo(this.title, ['code']);
    mustBeArray(this.title);
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
        this.title,
        [value],
        {
          grant_types: grants,
        },
        { responseTypes },
      );
    });
    allows(
      this.title,
      responseTypes,
      {
        grant_types: ['implicit', 'authorization_code'],
      },
      { responseTypes },
    );
    allows(
      this.title,
      ['token id_token'],
      {
        // mixed up order
        grant_types: ['implicit'],
      },
      { responseTypes },
      (client) => {
        expect(client.metadata().response_types).to.eql(['id_token token']);
      },
    );

    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, [], /must contain members$/);
    rejects(this.title, ['not-a-type']);
    rejects(this.title, ['not-a-type', 'none']);
  });

  context('sector_identifier_uri', function () {
    mustBeString(this.title);
    // must be a valid sector uri => GOTO: pairwise_clients.test.js
  });

  context('subject_type', function () {
    defaultsTo(this.title, 'public');
    defaultsTo(this.title, 'pairwise', undefined, { subjectTypes: ['pairwise'] });
    mustBeString(this.title);
    allows(this.title, 'public');
    rejects(this.title, 'not-a-type');
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

    context('token_endpoint_auth_method', function () {
      defaultsTo(this.title, 'client_secret_basic', undefined, configuration);
      mustBeString(this.title, undefined, undefined, configuration);
      rejects(
        this.title,
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
              this.title,
              value,
              {
                jwks: { keys: [sigKey] },
              },
              configuration,
            );
            break;
          case 'tls_client_auth':
            allows(
              this.title,
              value,
              {
                tls_client_auth_subject_dn: 'foo',
              },
              configuration,
            );
            allows(
              this.title,
              value,
              {
                tls_client_auth_san_dns: 'foo',
              },
              configuration,
            );
            allows(
              this.title,
              value,
              {
                tls_client_auth_san_uri: 'foo',
              },
              configuration,
            );
            allows(
              this.title,
              value,
              {
                tls_client_auth_san_ip: 'foo',
              },
              configuration,
            );
            allows(
              this.title,
              value,
              {
                tls_client_auth_san_email: 'foo',
              },
              configuration,
            );
            rejects(
              this.title,
              value,
              'tls_client_auth requires one of the certificate subject value parameters',
              undefined,
              configuration,
            );
            rejects(
              this.title,
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
            allows(this.title, value, undefined, configuration);
          }
        }
      });
      rejects(this.title, 'not-a-method', undefined, undefined, configuration);

      allows(
        this.title,
        'none',
        {
          response_types: ['id_token'],
          grant_types: ['implicit'],
        },
        configuration,
      );
    });

    context('token_endpoint_auth_signing_alg', function () {
      rejects(this.title, 'none');
      Object.entries({
        client_secret_jwt: ['HS', 'RS'],
        private_key_jwt: ['RS', 'HS', { jwks: { keys: [sigKey] } }],
      }).forEach(([method, [accepted, rejected, additional]]) => {
        allows(
          this.title,
          `${accepted}256`,
          {
            token_endpoint_auth_method: method,
            ...additional,
          },
          configuration,
        );

        rejects(
          this.title,
          `${rejected}256`,
          /^token_endpoint_auth_signing_alg must be/,
          {
            token_endpoint_auth_method: method,
            ...additional,
          },
          configuration,
        );

        rejects(
          this.title,
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

  context('userinfo_signed_response_alg', function () {
    const configuration = { features: { jwtUserinfo: { enabled: true } } };
    defaultsTo(this.title, undefined, undefined, configuration);
    mustBeString(this.title, undefined, undefined, configuration);
    allows(this.title, 'HS256', undefined, configuration);
    rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    rejects(this.title, 'none', undefined, undefined, configuration);
    rejects(
      this.title,
      undefined,
      'userinfo_signed_response_alg is mandatory property when userinfo_encrypted_response_alg is provided',
      { userinfo_encrypted_response_alg: 'dir' },
      merge({ features: { encryption: { enabled: true } } }, configuration),
    );
  });

  context('introspection_signed_response_alg', function () {
    const configuration = {
      features: {
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
      },
    };
    defaultsTo(this.title, 'RS256', undefined, configuration);
    mustBeString(this.title, undefined, undefined, configuration);
    allows(this.title, 'HS256', undefined, configuration);
    rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    rejects(this.title, 'none', undefined, undefined, configuration);
  });

  context('authorization_signed_response_alg', function () {
    const configuration = { features: { jwtResponseModes: { enabled: true } } };
    defaultsTo(this.title, 'RS256', undefined, configuration);
    mustBeString(this.title, undefined, undefined, configuration);
    allows(this.title, 'HS256', undefined, configuration);
    rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    rejects(this.title, 'none', undefined, undefined, configuration);
  });

  context('features.encryption', () => {
    const configuration = {
      features: {
        encryption: { enabled: true },
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
        jwtResponseModes: { enabled: true },
        jwtUserinfo: { enabled: true },
      },
    };

    context('id_token_encrypted_response_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(
        this.title,
        undefined,
        {
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      it('is required when id_token_encrypted_response_enc is also provided', () => assert.rejects(
        addClient(
          {
            id_token_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal(
            'id_token_encrypted_response_alg is mandatory property when id_token_encrypted_response_enc is provided',
          );
          return true;
        },
      ));
      allows(this.title, 'dir', undefined, configuration);
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
          this.title,
          value,
          {
            jwks: { keys: [sigKey] },
          },
          configuration,
        );
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    });

    context('id_token_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(
        this.title,
        'A128CBC-HS256',
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        this.title,
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        this.title,
        'not-an-enc',
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    context('userinfo_encrypted_response_alg', function () {
      const metadata = {
        jwks: { keys: [sigKey] },
        userinfo_signed_response_alg: 'RS256',
      };
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, metadata, configuration);
      it('is required when userinfo_encrypted_response_enc is also provided', () => assert.rejects(
        addClient(
          {
            userinfo_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal(
            'userinfo_encrypted_response_alg is mandatory property when userinfo_encrypted_response_enc is provided',
          );
          return true;
        },
      ));
      allows(this.title, 'dir', metadata, configuration);
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
        allows(this.title, value, metadata, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    });

    context('userinfo_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(
        this.title,
        'A128CBC-HS256',
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          [this.title.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        this.title,
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          [this.title.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              [this.title.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'dir',
              [this.title.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
            },
            configuration,
          );
        },
      );
      rejects(
        this.title,
        'not-an-enc',
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          [this.title.replace('encrypted', 'signed').replace('_enc', '_alg')]: 'RS256',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    context('introspection_encrypted_response_alg', function () {
      const metadata = {
        jwks: { keys: [sigKey] },
        introspection_signed_response_alg: 'RS256',
      };
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, metadata, configuration);
      it('is required when introspection_encrypted_response_enc is also provided', () => assert.rejects(
        addClient(
          {
            introspection_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal(
            'introspection_encrypted_response_alg is mandatory property when introspection_encrypted_response_enc is provided',
          );
          return true;
        },
      ));
      allows(this.title, 'dir', metadata, configuration);
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
        allows(this.title, value, metadata, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    });

    context('introspection_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(
        this.title,
        'A128CBC-HS256',
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        this.title,
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        this.title,
        'not-an-enc',
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
    });

    context('authorization_encrypted_response_alg', function () {
      const metadata = {
        jwks: { keys: [sigKey] },
        authorization_signed_response_alg: 'RS256',
      };
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, metadata, configuration);
      it('is required when authorization_encrypted_response_enc is also provided', () => assert.rejects(
        addClient(
          {
            authorization_encrypted_response_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal(
            'authorization_encrypted_response_alg is mandatory property when authorization_encrypted_response_enc is provided',
          );
          return true;
        },
      ));
      allows(this.title, 'dir', metadata, configuration);
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
        allows(this.title, value, metadata, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    });

    context('authorization_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(
        this.title,
        'A128CBC-HS256',
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      mustBeString(
        this.title,
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
          jwks: { keys: [sigKey] },
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
              jwks: { keys: [sigKey] },
            },
            configuration,
          );
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        this.title,
        'not-an-enc',
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
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
        requestObjects: { request: true },
      },
    };
    context('request_object_encryption_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, undefined, configuration);
      it('is required when request_object_encryption_enc is also provided', () => assert.rejects(
        addClient(
          {
            request_object_encryption_enc: 'whatever',
          },
          configuration,
        ),
        (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal(
            'request_object_encryption_alg is mandatory property when request_object_encryption_enc is provided',
          );
          return true;
        },
      ));
      allows(this.title, 'dir', undefined, configuration);
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
        allows(this.title, value, undefined, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
      rejects(this.title, 'none', undefined, undefined, configuration);
    });

    context('request_object_encryption_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(
        this.title,
        'A128CBC-HS256',
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
      mustBeString(
        this.title,
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
      ['A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
        (value) => {
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
            },
            configuration,
          );
          allows(
            this.title,
            value,
            {
              [this.title.replace(/(enc$)/, 'alg')]: 'dir',
            },
            configuration,
          );
        },
      );
      rejects(
        this.title,
        'not-an-enc',
        undefined,
        {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA-OAEP',
        },
        configuration,
      );
    });
  });

  describe('features.pushedAuthorizationRequests', () => {
    context('require_pushed_authorization_requests', function () {
      const configuration = (value = false) => ({
        features: {
          pushedAuthorizationRequests: {
            enabled: true,
            requirePushedAuthorizationRequests: value,
          },
        },
      });
      mustBeBoolean(this.title, undefined, configuration());
      mustBeBoolean(this.title, undefined, configuration(true));
      defaultsTo(this.title, false, undefined, configuration());
      defaultsTo(this.title, true, undefined, configuration(true));
      defaultsTo(
        this.title,
        true,
        {
          require_pushed_authorization_requests: false,
        },
        configuration(true),
      );
      defaultsTo(this.title, true, undefined, {
        ...configuration(),
        clientDefaults: { require_pushed_authorization_requests: true },
      });
    });
  });

  describe('features.dpop', () => {
    context('dpop_bound_access_tokens', function () {
      const configuration = {
        features: {
          dPoP: {
            enabled: true,
          },
        },
      };
      mustBeBoolean(this.title, undefined, configuration);
      mustBeBoolean(this.title, undefined, configuration);
      defaultsTo(this.title, false, undefined, configuration);
      defaultsTo(this.title, true, undefined, {
        ...configuration,
        clientDefaults: { dpop_bound_access_tokens: true },
      });
    });
  });

  describe('features.ciba', () => {
    const configuration = {
      features: {
        ciba: { enabled: true, deliveryModes: ['ping', 'poll'] },
        requestObjects: { request: false, requestUri: false },
      },
    };
    const metadata = {
      grant_types: ['urn:openid:params:grant-type:ciba'],
      redirect_uris: [],
      response_types: [],
      backchannel_token_delivery_mode: 'poll',
    };

    context('backchannel_user_code_parameter', function () {
      mustBeBoolean(this.title, undefined, configuration);
      defaultsTo(this.title, false, undefined, configuration);
    });

    context('backchannel_token_delivery_mode', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      isRequired(this.title, undefined, configuration, {
        ...metadata,
        backchannel_token_delivery_mode: undefined,
      });
    });

    context('backchannel_client_notification_endpoint', function () {
      isRequired(this.title, undefined, configuration, {
        ...metadata,
        backchannel_token_delivery_mode: 'ping',
      });
      mustBeUri(this.title, ['https'], configuration, {
        ...metadata,
        backchannel_token_delivery_mode: 'ping',
      });
    });

    context('backchannel_authentication_request_signing_alg', function () {
      const withRequestObjects = merge({}, configuration, {
        features: { requestObjects: { request: true } },
      });
      mustBeString(this.title, undefined, metadata, withRequestObjects);
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
        'EdDSA',
      ].forEach((alg) => {
        allows(this.title, alg, { ...metadata, jwks: { keys: [sigKey] } }, withRequestObjects);
      });
      rejects(this.title, 'not-an-alg', undefined, metadata, withRequestObjects);
      rejects(this.title, 'none', undefined, metadata, withRequestObjects);
      rejects(this.title, 'none', undefined, metadata, withRequestObjects);
      rejects(this.title, 'HS256', undefined, metadata, withRequestObjects);
      rejects(this.title, 'HS384', undefined, metadata, withRequestObjects);
      rejects(this.title, 'HS512', undefined, metadata, withRequestObjects);
      defaultsTo(this.title, undefined, undefined, withRequestObjects);
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
        expect(sectorIdentifier(client)).to.eql('rp.example.com');
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
        expect(sectorIdentifier(client)).to.eql('rp.example.com');
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

  context('jwks', function () {
    const configuration = {
      features: {
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
        revocation: { enabled: true },
        encryption: { enabled: true },
        jwtUserinfo: { enabled: true },
        ciba: { enabled: true },
        requestObjects: { request: true },
      },
    };

    [false, Boolean, 'foo', 123, null, { kty: null }, { kty: '' }].forEach((value) => {
      rejects(this.title, { keys: [value] }, 'client JSON Web Key Set is invalid');
    });
    rejects('jwks', 'string', 'client JSON Web Key Set is invalid');
    rejects('jwks', null, 'client JSON Web Key Set is invalid');
    rejects(this.title, {}, 'client JSON Web Key Set is invalid');
    rejects(this.title, 1, 'client JSON Web Key Set is invalid');
    rejects(this.title, 0, 'client JSON Web Key Set is invalid');
    rejects(this.title, true, 'client JSON Web Key Set is invalid');
    rejects(this.title, { keys: [privateKey] }, 'client JSON Web Key Set is invalid');
    rejects(
      this.title,
      { keys: [{ k: '6vl9Rlk88HO8onFHq0ZvTtga68vkUr-bRZ2Hvxu-rAw', kty: 'oct' }] },
      'client JSON Web Key Set is invalid',
    );
    rejects(
      this.title,
      { keys: [{ kty: 'oct', kid: 'jf1nb1YotqxK9viWsXMsngnTCmO2r3w_moVIPtaf8wU' }] },
      'client JSON Web Key Set is invalid',
    );
    allows(this.title, { keys: [{ kty: 'unrecognized' }] });
    allows(this.title, { keys: [] });
    rejects(
      this.title,
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
      rejects(
        this.title,
        undefined,
        'jwks or jwks_uri is mandatory for this client',
        {
          [prop]: 'RS256',
        },
        configuration,
      );
      rejects(
        this.title,
        undefined,
        'jwks or jwks_uri is mandatory for this client',
        {
          [prop]: 'ES384',
        },
        configuration,
      );
    }

    [
      'id_token_encrypted_response_alg',
      'userinfo_encrypted_response_alg',
      'introspection_encrypted_response_alg',
    ].forEach((prop) => {
      ['RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'].forEach(
        (alg) => {
          rejects(
            this.title,
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

  context('features.mTLS.certificateBoundAccessTokens', () => {
    context('tls_client_certificate_bound_access_tokens', function () {
      const configuration = {
        features: {
          mTLS: { enabled: true, certificateBoundAccessTokens: true },
        },
      };

      defaultsTo(this.title, false, undefined, configuration);
      defaultsTo(this.title, undefined);
      mustBeBoolean(this.title, undefined, configuration);
    });
  });

  context('features.backchannelLogout', () => {
    const configuration = {
      features: {
        backchannelLogout: { enabled: true },
      },
    };

    context('backchannel_logout_uri', function () {
      defaultsTo(this.title, undefined);
      mustBeString(this.title, undefined, undefined, configuration);
      mustBeUri(this.title, ['http', 'https'], configuration);
    });

    context('backchannel_logout_session_required', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, false, undefined, configuration);
      mustBeBoolean(this.title, undefined, configuration);
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

    context('tls_client_auth_subject_dn', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      allows(
        this.title,
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows(this.title, 'foo', undefined, configuration, (client) => {
        expect(client.metadata()[this.title]).to.eql(undefined);
      });
    });

    context('tls_client_auth_san_dns', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      allows(
        this.title,
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows(this.title, 'foo', undefined, configuration, (client) => {
        expect(client.metadata()[this.title]).to.eql(undefined);
      });
    });

    context('tls_client_auth_san_uri', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      allows(
        this.title,
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows(this.title, 'foo', undefined, configuration, (client) => {
        expect(client.metadata()[this.title]).to.eql(undefined);
      });
    });

    context('tls_client_auth_san_ip', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      allows(
        this.title,
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows(this.title, 'foo', undefined, configuration, (client) => {
        expect(client.metadata()[this.title]).to.eql(undefined);
      });
    });

    context('tls_client_auth_san_email', function () {
      mustBeString(this.title, undefined, undefined, configuration);
      allows(
        this.title,
        'foo',
        {
          token_endpoint_auth_method: 'tls_client_auth',
        },
        configuration,
      );
      allows(this.title, 'foo', undefined, configuration, (client) => {
        expect(client.metadata()[this.title]).to.eql(undefined);
      });
    });
  }

  context('jwks_uri', function () {
    mustBeString(this.title);

    // more in client_keystore.test.js
  });

  it('allows unrecognized properties but does not yield them back', () => addClient({
    unrecognized: true,
  }).then((client) => {
    expect(client).not.to.have.property('unrecognized');
  }));

  it('allows clients without grants, for introspection, revocation (RS clients)', () => addClient({
    client_id: 'authorization-server',
    client_secret: 'foobar',
    redirect_uris: [],
    response_types: [],
    grant_types: [],
  }).then((client) => {
    expect(client.grantTypes).to.be.empty;
    expect(client.responseTypes).to.be.empty;
    expect(client.redirectUris).to.be.empty;
  }));

  it('allows clients only with client_credentials', () => addClient(
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
    expect(client.grantTypes).not.to.be.empty;
    expect(client.responseTypes).to.be.empty;
    expect(client.redirectUris).to.be.empty;
  }));

  it('fails to determine sector identifier', () => addClient(
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
    expect(client.grantTypes).to.be.empty;
    expect(client.responseTypes).to.be.empty;
    expect(client.redirectUris).to.be.empty;
    expect(() => sectorIdentifier(client)).to.throw();
    try {
      sectorIdentifier(client);
    } catch (err) {
      expect(err.error).to.eql('invalid_client_metadata');
      expect(err.error_description).to.eql('could not determine a sector identifier');
    }
  }));

  context(
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
});
