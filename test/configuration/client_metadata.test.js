const util = require('util');

const { expect } = require('chai');
const camelCase = require('lodash/camelCase');
const merge = require('lodash/merge');
const omit = require('lodash/omit');
const pull = require('lodash/pull');
const cloneDeep = require('lodash/cloneDeep');

const runtimeSupport = require('../../lib/helpers/runtime_support');
const { Provider } = require('../../lib');
const { whitelistedJWA } = require('../default.config');
const mtlsKeys = require('../jwks/jwks.json');

const sigKey = global.keystore.get().toJWK();
const privateKey = global.keystore.get().toJWK(true);
const { DYNAMIC_SCOPE_LABEL, errors: { InvalidClientMetadata } } = Provider;

describe('Client metadata validation', () => {
  let DefaultProvider;
  before(() => {
    DefaultProvider = new Provider('http://localhost', {
      jwks: global.keystore.toJWKS(true),
      whitelistedJWA: cloneDeep(whitelistedJWA),
    });
  });

  function addClient(meta, configuration) {
    let provider;
    if (configuration) {
      provider = new Provider('http://localhost', merge({
        jwks: global.keystore.toJWKS(true),
        whitelistedJWA: cloneDeep(whitelistedJWA),
      }, configuration));
    } else {
      provider = DefaultProvider;
    }

    return i(provider).clientAdd({
      client_id: 'client',
      client_secret: 'its64bytes_____________________________________________________!',
      redirect_uris: ['https://client.example.com/cb'],
      ...meta,
    });
  }

  const fail = () => { throw new Error('expected promise to be rejected'); };

  const mustBeString = (prop, values = [[], 123, true, null, false, {}, ''], meta, configuration) => {
    values.forEach((value) => {
      let msg = util.format('must be a string, %j provided', value);
      if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => addClient({ ...meta, [prop]: value }, configuration).then(fail, (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        expect(err.error_description).to.equal(`${prop} must be a non-empty string if provided`);
      }));
    });
  };

  const mustBeUri = (prop, protocols, configuration) => {
    it('must be a uri', () => addClient({
      [prop]: 'whatever://not but not a uri',
    }, configuration).then(fail, (err) => {
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
    }));

    protocols.forEach((protocol) => {
      it(`can be ${protocol} uri`, () => addClient({
        [prop]: `${protocol}://example.com/${prop}`,
      }));
    });
  };

  const mustBeArray = (prop, values = [{}, 'string', 123, true, null, false], configuration) => {
    values.forEach((value) => {
      let msg = util.format('must be a array, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => addClient({
        [prop]: value,
      }, configuration).then(fail, (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        expect(err.error_description).to.equal(`${prop} must be an array`);
      }));
    });
  };

  const mustBeBoolean = (prop, meta, configuration) => {
    [{}, 'string', 123, null, []].forEach((value) => {
      let msg = util.format('must be a boolean, %j provided', value);
      if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => addClient({
        [prop]: value,
      }, configuration).then(fail, (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        expect(err.error_description).to.equal(`${prop} must be a boolean`);
      }));
    });
  };

  const defaultsTo = (prop, value, meta, configuration) => {
    let msg = util.format('defaults to %s', value);
    if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);

    it(msg, () => addClient(meta, configuration).then((client) => {
      if (value === undefined) {
        expect(client.metadata()).not.to.have.property(prop);
      } else {
        expect(client.metadata()).to.have.property(prop).and.eql(value);
      }
    }));
  };

  const isRequired = (prop, values, configuration) => {
    (values || [null, undefined, '']).forEach((value) => {
      let msg = util.format('is required, %j provided', value);
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => addClient({
        [prop]: value,
      }, configuration).then(fail, (err) => {
        if (prop === 'redirect_uris') {
          expect(err.message).to.equal('invalid_redirect_uri');
        } else {
          expect(err.message).to.equal('invalid_client_metadata');
        }
        expect(err.error_description).to.equal(`${prop} is mandatory property`);
      }));
    });
  };

  const allows = (prop, value, meta, configuration, assertion = (client) => {
    expect(client.metadata()[prop]).to.eql(value);
  }) => {
    let msg = util.format('passes %j', value);
    if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    it(msg, () => addClient({ ...meta, [prop]: value }, configuration).then(assertion, (err) => {
      if (err instanceof InvalidClientMetadata) {
        throw new Error(`InvalidClientMetadata received ${err.message} ${err.error_description}`);
      }
    }));
  };

  const rejects = (prop, value, description, meta, configuration) => {
    let msg = util.format('rejects %j', value);
    if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    it(msg, () => addClient({ ...meta, [prop]: value }, configuration).then(fail, (err) => {
      if (prop === 'redirect_uris') {
        expect(err.message).to.equal('invalid_redirect_uri');
      } else {
        expect(err.message).to.equal('invalid_client_metadata');
      }
      if (description) {
        const assert = description.exec ? 'match' : 'equal';
        expect(err.error_description).to[assert](description);
      }
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
  });

  context('client_name', function () {
    mustBeString(this.title);
    allows(this.title, 'whatever client name');
  });

  context('client_secret', function () {
    isRequired(this.title);
    mustBeString(this.title, [123, {}, [], true]);
    allows(this.title, 'whatever client secret');
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
    rejects(this.title, ['not a member'], 'default_acr_values must be empty (no values are allowed)');
    rejects(this.title, ['not a member', '1', 'default_acr_values must be empty (no values are allowed)']);
    rejects(this.title, ['not a member'], "default_acr_values can only contain '0', '1', or '2'", undefined, { acrValues });
    rejects(this.title, ['not a member', '1'], "default_acr_values can only contain '0', '1', or '2'", undefined, { acrValues });
  });

  context('require_signed_request_object', function () {
    const configuration = (value = false, requestUri = true) => ({
      features: {
        requestObjects: {
          requestUri,
          requireSignedRequestObject: value,
        },
      },
    });
    mustBeBoolean(this.title);
    defaultsTo(this.title, undefined, undefined, configuration(false, false));
    defaultsTo(this.title, false, undefined, configuration());
    defaultsTo(this.title, true, undefined, configuration(true));
    defaultsTo(this.title, true, {
      require_signed_request_object: false,
    }, configuration(true));
    defaultsTo(this.title, true, undefined, {
      ...configuration(),
      clientDefaults: { require_signed_request_object: true },
    });
    rejects(this.title, true, 'request_object_signing_alg must not be "none" when require_signed_request_object is true', { request_object_signing_alg: 'none' });
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
    rejects(this.title, ['implicit'], undefined, { // misses authorization_code
      response_types: ['id_token', 'code'],
    });
    rejects(this.title, ['authorization_code'], undefined, { // misses implicit
      response_types: ['id_token'],
    });
    rejects(this.title, ['authorization_code'], undefined, { // misses implicit
      response_types: ['token'],
    });
  });

  context('id_token_signed_response_alg', function () {
    defaultsTo(this.title, 'RS256');
    mustBeString(this.title);
    rejects(this.title, 'none', undefined, {
      response_types: ['code id_token'],
    });
  });

  [
    'client_uri', 'logo_uri', 'policy_uri', 'tos_uri',
  ].forEach((prop) => {
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
    const SIGN = /^sign:[a-fA-F0-9]{2,}$/;
    SIGN[DYNAMIC_SCOPE_LABEL] = 'sign:{hex}';

    mustBeString(this.title);
    allows(this.title, undefined);
    allows(this.title, 'openid');
    allows(this.title, 'offline_access');
    allows(this.title, 'openid offline_access');
    allows(this.title, 'openid profile', undefined, { scopes: ['profile'] });
    allows(this.title, 'openid profile', undefined, { claims: { profile: ['given_name'] } });
    allows(this.title, 'profile', undefined, { scopes: ['profile'] });
    allows(this.title, 'profile', undefined, { claims: { profile: ['given_name'] } });
    allows(this.title, 'openid sign:{hex}', undefined, { dynamicScopes: [SIGN] });
    allows(this.title, 'openid sign:{hex}', undefined, { claims: new Map([[SIGN, ['given_name']]]) });
    allows(this.title, 'sign:{hex}', undefined, { dynamicScopes: [SIGN] });
    allows(this.title, 'sign:{hex}', undefined, { claims: new Map([[SIGN, ['given_name']]]) });
    rejects(this.title, 'foo', /must only contain supported scopes/);
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
    rejects(this.title, ['https://rp.example.com#whatever'], /redirect_uris must not contain fragments$/, {
      application_type: 'web',
    });
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
    mustBeString(this.title);
    [
      'none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
      'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', runtimeSupport.EdDSA ? 'EdDSA' : false,
    ].filter(Boolean).forEach((alg) => {
      allows(this.title, alg, { jwks: { keys: [sigKey] } });
    });
    rejects(this.title, 'not-an-alg');
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
    mustBeArray(this.title);

    allows(this.title, ['https://a-web-uri']);
    allows(this.title, ['http://a-web-uri'], /must only contain https uris$/);
    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, ['not a uri'], /request_uris must only contain web uris$/);
    rejects(this.title, ['custom-scheme://not-a-web-uri'], /request_uris must only contain web uris$/);
    rejects(this.title, ['urn:example'], /request_uris must only contain web uris$/);
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
    rejects(this.title, ['custom-scheme://not-a-web-uri'], /must only contain web uris$/, undefined, configuration);
    rejects(this.title, ['https://example.com/'], /must only contain origins$/, undefined, configuration);
    rejects(this.title, ['https://example.com?'], /must only contain origins$/, undefined, configuration);
    rejects(this.title, ['https://example.com#'], /must only contain origins$/, undefined, configuration);
    rejects(this.title, ['https://foo:bar@example.com'], /must only contain origins$/, undefined, configuration);
    rejects(this.title, ['https://foo@example.com'], /must only contain origins$/, undefined, configuration);
  });

  context('require_auth_time', function () {
    defaultsTo(this.title, false);
    mustBeBoolean(this.title);
  });

  context('response_types', function () {
    defaultsTo(this.title, ['code']);
    mustBeArray(this.title);
    const responseTypes = ['code id_token token', 'code id_token', 'code token', 'code', 'id_token token', 'id_token', 'none'];
    responseTypes.forEach((value) => {
      const grants = [];
      if (value.includes('token')) {
        grants.push('implicit');
      }
      if (value.includes('code')) {
        grants.push('authorization_code');
      }
      allows(this.title, [value], {
        grant_types: grants,
      }, { responseTypes });
    });
    allows(this.title, responseTypes, {
      grant_types: ['implicit', 'authorization_code'],
    }, { responseTypes });
    allows(this.title, ['token id_token'], { // mixed up order
      grant_types: ['implicit'],
    }, { responseTypes }, (client) => {
      expect(client.metadata().response_types).to.eql(['id_token token']);
    });

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

  context('post_logout_redirect_uris', function () {
    defaultsTo(this.title, [], undefined);
    defaultsTo(this.title, [], { post_logout_redirect_uris: undefined });
    mustBeArray(this.title, undefined);

    rejects(this.title, [123], /must only contain strings$/, undefined);
    allows(this.title, ['http://a-web-uri'], undefined);
    allows(this.title, ['https://a-web-uri'], undefined);
    allows(this.title, ['any-custom-scheme://not-a-web-uri'], undefined);
    rejects(this.title, ['not a uri'], /must only contain uris$/, undefined);
  });

  [
    'token_endpoint_auth_method',
    'introspection_endpoint_auth_method',
    'revocation_endpoint_auth_method',
  ].forEach((endpointAuthMethodProperty) => {
    const configuration = {
      [`${endpointAuthMethodProperty.split('_')[0]}EndpointAuthMethods`]: [
        'none',
        'client_secret_basic',
        'client_secret_post',
        'private_key_jwt',
        'client_secret_jwt',
        runtimeSupport.KeyObject ? 'tls_client_auth' : false,
      ].filter(Boolean),
      features: {
        mTLS: {
          enabled: runtimeSupport.KeyObject, selfSignedTlsClientAuth: true, tlsClientAuth: true,
        },
      },
    };

    if (!endpointAuthMethodProperty.startsWith('token')) {
      Object.assign(configuration.features, { [endpointAuthMethodProperty.split('_')[0]]: { enabled: true } });
    }

    context(endpointAuthMethodProperty, function () {
      defaultsTo(this.title, 'client_secret_basic', undefined, configuration);
      mustBeString(this.title, undefined, undefined, configuration);
      rejects(this.title, 'foo', `${endpointAuthMethodProperty} must not be provided (no values are allowed)`, undefined, {
        ...configuration,
        [`${endpointAuthMethodProperty.split('_')[0]}EndpointAuthMethods`]: [],
      });

      [
        'client_secret_basic', 'client_secret_jwt', 'client_secret_post', 'private_key_jwt', 'tls_client_auth',
      ].forEach((value) => {
        switch (value) {
          case 'private_key_jwt':
            allows(this.title, value, {
              jwks: { keys: [sigKey] },
            }, configuration);
            break;
          case 'tls_client_auth':
            if (runtimeSupport.KeyObject) {
              allows(this.title, value, {
                tls_client_auth_subject_dn: 'foo',
              }, configuration);
              allows(this.title, value, {
                tls_client_auth_san_dns: 'foo',
              }, configuration);
              allows(this.title, value, {
                tls_client_auth_san_uri: 'foo',
              }, configuration);
              allows(this.title, value, {
                tls_client_auth_san_ip: 'foo',
              }, configuration);
              allows(this.title, value, {
                tls_client_auth_san_email: 'foo',
              }, configuration);
              rejects(this.title, value, 'tls_client_auth requires one of the certificate subject value parameters', undefined, configuration);
              rejects(this.title, value, 'only one tls_client_auth certificate subject value must be provided', {
                tls_client_auth_san_ip: 'foo',
                tls_client_auth_san_email: 'foo',
              }, configuration);
            }
            break;
          default: {
            allows(this.title, value, undefined, configuration);
          }
        }
      });
      rejects(this.title, 'not-a-method', undefined, undefined, configuration);

      allows(this.title, 'none', {
        response_types: ['id_token'],
        grant_types: ['implicit'],
      }, configuration);
    });

    const endpointAuthSigningAlgProperty = endpointAuthMethodProperty.replace('_method', '_signing_alg');
    context(endpointAuthSigningAlgProperty, function () {
      Object.entries({
        client_secret_jwt: ['HS', 'RS'],
        private_key_jwt: ['RS', 'HS', { jwks: { keys: [sigKey] } }],
      }).forEach(([method, [accepted, rejected, additional]]) => {
        allows(this.title, `${accepted}256`, {
          [endpointAuthMethodProperty]: method,
          ...additional,
        }, configuration);

        rejects(this.title, `${rejected}256`, new RegExp(`^${endpointAuthSigningAlgProperty} must be`), {
          [endpointAuthMethodProperty]: method,
          ...additional,
        }, configuration);

        const confProperty = `${camelCase(endpointAuthSigningAlgProperty)}Values`;
        rejects(this.title, `${accepted}384`, new RegExp(`^${endpointAuthSigningAlgProperty} must be`), {
          [endpointAuthMethodProperty]: method,
          ...additional,
        }, {
          whitelistedJWA: {
            [confProperty]: pull(cloneDeep(whitelistedJWA[confProperty]), `${accepted}384`),
          },
          ...configuration,
        });
      });
    });
  });

  context('userinfo_signed_response_alg', function () {
    defaultsTo(this.title, undefined);
    mustBeString(this.title);
    allows(this.title, 'HS256');
    rejects(this.title, 'not-an-alg');
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
      },
    };

    context('id_token_encrypted_response_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, {
        jwks: { keys: [sigKey] },
      }, configuration);
      it('is required when id_token_encrypted_response_enc is also provided', () => addClient({
        id_token_encrypted_response_enc: 'whatever',
      }, configuration).then(fail, (err) => {
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.equal('id_token_encrypted_response_alg is mandatory property when id_token_encrypted_response_enc is provided');
      }));
      allows(this.title, 'dir', undefined, configuration);
      [
        'RSA-OAEP', ...(runtimeSupport.oaepHash ? ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'] : []), 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].filter(Boolean).forEach((value) => {
        allows(this.title, value, {
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('id_token_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, 'A128CBC-HS256', {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'dir',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
    });

    context('userinfo_encrypted_response_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, {
        jwks: { keys: [sigKey] },
      }, configuration);
      it('is required when userinfo_encrypted_response_enc is also provided', () => addClient({
        userinfo_encrypted_response_enc: 'whatever',
      }, configuration).then(fail, (err) => {
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.equal('userinfo_encrypted_response_alg is mandatory property when userinfo_encrypted_response_enc is provided');
      }));
      allows(this.title, 'dir', undefined, configuration);
      [
        'RSA-OAEP', ...(runtimeSupport.oaepHash ? ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'] : []), 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].filter(Boolean).forEach((value) => {
        allows(this.title, value, {
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('userinfo_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(this.title, 'A128CBC-HS256', {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'dir',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
    });

    context('introspection_encrypted_response_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, {
        jwks: { keys: [sigKey] },
      }, configuration);
      it('is required when introspection_encrypted_response_enc is also provided', () => addClient({
        introspection_encrypted_response_enc: 'whatever',
      }, configuration).then(fail, (err) => {
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.equal('introspection_encrypted_response_alg is mandatory property when introspection_encrypted_response_enc is provided');
      }));
      allows(this.title, 'dir', undefined, configuration);
      [
        'RSA-OAEP', ...(runtimeSupport.oaepHash ? ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'] : []), 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].filter(Boolean).forEach((value) => {
        allows(this.title, value, {
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('introspection_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(this.title, 'A128CBC-HS256', {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'dir',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
    });

    context('authorization_encrypted_response_alg', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      mustBeString(this.title, undefined, {
        jwks: { keys: [sigKey] },
      }, configuration);
      it('is required when authorization_encrypted_response_enc is also provided', () => addClient({
        authorization_encrypted_response_enc: 'whatever',
      }, configuration).then(fail, (err) => {
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.equal('authorization_encrypted_response_alg is mandatory property when authorization_encrypted_response_enc is provided');
      }));
      allows(this.title, 'dir', undefined, configuration);
      [
        'RSA-OAEP', ...(runtimeSupport.oaepHash ? ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'] : []), 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].filter(Boolean).forEach((value) => {
        allows(this.title, value, {
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('authorization_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(this.title, 'A128CBC-HS256', {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'dir',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
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
      it('is required when request_object_encryption_enc is also provided', () => addClient({
        request_object_encryption_enc: 'whatever',
      }, configuration).then(fail, (err) => {
        expect(err.message).to.equal('invalid_client_metadata');
        expect(err.error_description).to.equal('request_object_encryption_alg is mandatory property when request_object_encryption_enc is provided');
      }));
      allows(this.title, 'dir', undefined, configuration);
      [
        'RSA-OAEP', ...(runtimeSupport.oaepHash ? ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'] : []), 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].filter(Boolean).forEach((value) => {
        allows(this.title, value, undefined, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('request_object_encryption_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(this.title, 'A128CBC-HS256', {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
      }, configuration);
      mustBeString(this.title, undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
        }, configuration);
        allows(this.title, value, {
          [this.title.replace(/(enc$)/, 'alg')]: 'dir',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        [this.title.replace(/(enc$)/, 'alg')]: 'RSA1_5',
      }, configuration);
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
      defaultsTo(this.title, true, {
        require_pushed_authorization_requests: false,
      }, configuration(true));
      defaultsTo(this.title, true, undefined, {
        ...configuration(),
        clientDefaults: { require_pushed_authorization_requests: true },
      });
    });
  });

  context('jwks', function () {
    const configuration = {
      features: {
        introspection: { enabled: true },
        jwtIntrospection: { enabled: true },
        revocation: { enabled: true },
        encryption: { enabled: true },
      },
    };

    [false, Boolean, 'foo', 123, null, { kty: null }, { kty: '' }].forEach((value) => {
      rejects(this.title, { keys: [value] }, 'jwks keys member index 0 is not a valid JWK');
    });
    rejects(this.title, 'string', 'jwks must be a JWK Set');
    rejects(this.title, {}, 'jwks must be a JWK Set');
    rejects(this.title, 1, 'jwks must be a JWK Set');
    rejects(this.title, 0, 'jwks must be a JWK Set');
    rejects(this.title, true, 'jwks must be a JWK Set');
    rejects(this.title, { keys: [privateKey] }, 'jwks must not contain private or symmetric keys (found in keys member index 0)');
    rejects(this.title, { keys: [{ k: '6vl9Rlk88HO8onFHq0ZvTtga68vkUr-bRZ2Hvxu-rAw', kty: 'oct' }] }, 'jwks must not contain private or symmetric keys (found in keys member index 0)');
    rejects(this.title, { keys: [{ kty: 'oct', kid: 'jf1nb1YotqxK9viWsXMsngnTCmO2r3w_moVIPtaf8wU' }] }, 'jwks must not contain private or symmetric keys (found in keys member index 0)');
    allows(this.title, { keys: [{ kty: 'unrecognized' }] });
    allows(this.title, { keys: [] });
    ['introspection', 'revocation', 'token'].forEach((endpoint) => {
      rejects(this.title, undefined, 'jwks or jwks_uri is mandatory for this client', {
        [`${endpoint}_endpoint_auth_method`]: 'private_key_jwt',
      }, configuration);
    });
    rejects(this.title, undefined, 'jwks or jwks_uri is mandatory for this client', {
      request_object_signing_alg: 'RS256',
    });
    rejects(this.title, undefined, 'jwks or jwks_uri is mandatory for this client', {
      request_object_signing_alg: 'ES384',
    });

    if (runtimeSupport.KeyObject) {
      const invalidx5c = cloneDeep(mtlsKeys);
      invalidx5c.keys[0].x5c = true;
      rejects(this.title, invalidx5c, 'jwks keys member index 0 is not a valid EC JWK (`x5c` must be an array of one or more PKIX certificates when provided)');

      const emptyx5c = cloneDeep(mtlsKeys);
      emptyx5c.keys[0].x5c = [];
      rejects(this.title, emptyx5c, 'jwks keys member index 0 is not a valid EC JWK (`x5c` must be an array of one or more PKIX certificates when provided)');

      const invalidCert = cloneDeep(mtlsKeys);
      invalidCert.keys[0].x5c = ['foobar'];
      rejects(this.title, invalidCert, 'jwks keys member index 0 is not a valid EC JWK (`x5c` member at index 0 is not a valid base64-encoded DER PKIX certificate)');
    }

    [
      'id_token_encrypted_response_alg',
      'userinfo_encrypted_response_alg',
      'introspection_encrypted_response_alg',
    ].forEach((prop) => {
      [
        'RSA-OAEP', 'RSA1_5',
        'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
      ].forEach((alg) => {
        rejects(this.title, undefined, 'jwks or jwks_uri is mandatory for this client', {
          [prop]: alg,
        }, configuration);
      });
    });
    rejects(this.title, { keys: ['something'] }, 'jwks and jwks_uri must not be used at the same time', {
      jwks_uri: 'https://client.example.com/jwks',
    });
  });

  if (runtimeSupport.KeyObject) {
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
  }

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
      rejects(this.title, 'https://rp.example.com/bcl', 'id_token_signed_response_alg must not be "none" when backchannel_logout_uri is used', { id_token_signed_response_alg: 'none' }, configuration);
    });

    context('backchannel_logout_session_required', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, false, undefined, configuration);
      mustBeBoolean(this.title, undefined, configuration);
    });
  });

  context('features.frontchannelLogout', () => {
    const configuration = {
      features: {
        frontchannelLogout: { enabled: true },
      },
    };

    context('frontchannel_logout_uri', function () {
      defaultsTo(this.title, undefined);
      mustBeString(this.title, undefined, undefined, configuration);
      mustBeUri(this.title, ['http', 'https'], configuration);
    });

    context('frontchannel_logout_session_required', function () {
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
      tokenEndpointAuthMethods: ['tls_client_auth', 'client_secret_basic'],
    };

    if (runtimeSupport.KeyObject) {
      context('tls_client_auth_subject_dn', function () {
        mustBeString(this.title, undefined, undefined, configuration);
        allows(this.title, 'foo', {
          token_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          revocation_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          introspection_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', undefined, configuration, (client) => {
          expect(client.metadata()[this.title]).to.eql(undefined);
        });
      });

      context('tls_client_auth_san_dns', function () {
        mustBeString(this.title, undefined, undefined, configuration);
        allows(this.title, 'foo', {
          token_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          revocation_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          introspection_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', undefined, configuration, (client) => {
          expect(client.metadata()[this.title]).to.eql(undefined);
        });
      });

      context('tls_client_auth_san_uri', function () {
        mustBeString(this.title, undefined, undefined, configuration);
        allows(this.title, 'foo', {
          token_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          revocation_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          introspection_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', undefined, configuration, (client) => {
          expect(client.metadata()[this.title]).to.eql(undefined);
        });
      });

      context('tls_client_auth_san_ip', function () {
        mustBeString(this.title, undefined, undefined, configuration);
        allows(this.title, 'foo', {
          token_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          revocation_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          introspection_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', undefined, configuration, (client) => {
          expect(client.metadata()[this.title]).to.eql(undefined);
        });
      });

      context('tls_client_auth_san_email', function () {
        mustBeString(this.title, undefined, undefined, configuration);
        allows(this.title, 'foo', {
          token_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          revocation_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', {
          introspection_endpoint_auth_method: 'tls_client_auth',
        }, configuration);
        allows(this.title, 'foo', undefined, configuration, (client) => {
          expect(client.metadata()[this.title]).to.eql(undefined);
        });
      });
    }
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

  it('allows clients only with client_credentials', () => addClient({
    client_id: 'resource-server',
    client_secret: 'foobar',
    redirect_uris: [],
    response_types: [],
    grant_types: ['client_credentials'],
  }, {
    features: { clientCredentials: { enabled: true } },
  }).then((client) => {
    expect(client.grantTypes).not.to.be.empty;
    expect(client.responseTypes).to.be.empty;
    expect(client.redirectUris).to.be.empty;
  }));

  context('clientDefaults configuration option allows for default client metadata to be changed', () => {
    defaultsTo('token_endpoint_auth_method', 'client_secret_post', undefined, {
      clientDefaults: {
        token_endpoint_auth_method: 'client_secret_post',
      },
    });
    defaultsTo('introspection_endpoint_auth_method', 'client_secret_post', undefined, {
      features: {
        introspection: { enabled: true },
      },
      clientDefaults: {
        token_endpoint_auth_method: 'client_secret_post',
      },
    });
    defaultsTo('introspection_endpoint_auth_signing_alg', 'HS384', { token_endpoint_auth_method: 'client_secret_jwt' }, {
      features: {
        introspection: { enabled: true },
      },
      clientDefaults: {
        token_endpoint_auth_signing_alg: 'HS384',
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
  });
});
