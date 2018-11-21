const util = require('util');

const { expect } = require('chai');
const {
  camelCase, omit, pull, cloneDeep,
} = require('lodash');

const Provider = require('../../lib');
const { whitelistedJWA } = require('../default.config');
const mtlsKeys = require('../jwks/jwks.json');

const sigKey = global.keystore.get().toJSON(true);
const { InvalidClientMetadata } = Provider.errors;

describe('Client metadata validation', () => {
  let DefaultProvider;
  before(() => {
    DefaultProvider = new Provider('http://localhost', {
      whitelistedJWA: cloneDeep(whitelistedJWA),
    });

    return DefaultProvider.initialize({
      keystore: global.keystore,
    });
  });

  function addClient(meta, configuration) {
    let prom;
    if (configuration) {
      const provider = new Provider('http://localhost', Object.assign({}, { whitelistedJWA }, configuration));

      prom = provider.initialize({
        keystore: global.keystore,
      }).then(() => provider);
    } else {
      prom = Promise.resolve(DefaultProvider);
    }

    return prom.then(provider => i(provider).clientAdd(Object.assign({
      client_id: 'client',
      client_secret: 'its64bytes_____________________________________________________!',
      redirect_uris: ['https://client.example.com/cb'],
    }, meta)));
  }

  const fail = () => { throw new Error('expected promise to be rejected'); };

  const mustBeString = (prop, values = [[], 123, true, null, false, {}, ''], meta, configuration) => {
    values.forEach((value) => {
      let msg = util.format('must be a string, %j provided', value);
      if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
      if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
      it(msg, () => addClient(Object.assign({}, meta, {
        [prop]: value,
      }), configuration).then(fail, (err) => {
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
    it(msg, () => addClient(Object.assign({}, meta, {
      [prop]: value,
    }), configuration).then(assertion, (err) => {
      if (err instanceof InvalidClientMetadata) {
        throw new Error(`InvalidClientMetadata received ${err.message} ${err.error_description}`);
      }
    }));
  };

  const rejects = (prop, value, description, meta, configuration) => {
    let msg = util.format('rejects %j', value);
    if (meta) msg = util.format(`${msg}, [client %j]`, omit(meta, ['jwks.keys']));
    if (configuration) msg = util.format(`${msg}, [provider %j]`, configuration);
    it(msg, () => addClient(Object.assign({}, meta, {
      [prop]: value,
    }), configuration).then(fail, (err) => {
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
    rejects(this.title, 'foobar', 'application_type must be one of [native,web]');
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
    rejects(this.title, ['not a member']);
    rejects(this.title, ['not a member', '1']);
  });

  context('default_max_age', function () {
    allows(this.title, 5);
    rejects(this.title, 0);
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
    rejects(this.title, ['https://some#whatever'], undefined, {
      application_type: 'web',
    });
    rejects(this.title, ['web-custom-scheme://some'], undefined, {
      application_type: 'web',
    });
    rejects(this.title, ['https://localhost'], undefined, {
      application_type: 'web',
      grant_types: ['implicit', 'authorization_code'],
      response_types: ['code id_token'],
    });
    allows(this.title, ['http://localhost'], undefined, {
      application_type: 'web',
    });
    allows(this.title, ['http://localhost'], {
      application_type: 'native',
    }, {
      features: {
        oauthNativeApps: false,
      },
    });
    allows(this.title, ['native://localhost'], {
      application_type: 'native',
    }, {
      features: {
        oauthNativeApps: false,
      },
    });
    rejects(this.title, ['http://some'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['http://some'], undefined, {
      application_type: 'native',
    }, {
      features: {
        oauthNativeApps: false,
      },
    });
    rejects(this.title, ['not-a-uri'], undefined, {
      application_type: 'native',
    });
    rejects(this.title, ['not-a-uri'], undefined, {
      application_type: 'native',
    }, {
      features: {
        oauthNativeApps: false,
      },
    });
    rejects(this.title, ['https://localhost/foo/bar'], undefined, {
      application_type: 'native',
    }, {
      features: {
        oauthNativeApps: false,
      },
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
      'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512',
    ].forEach((alg) => {
      allows(this.title, alg, { jwks: { keys: [sigKey] } });
    });
    rejects(this.title, 'not-an-alg');
  });

  context('request_uris', function () {
    defaultsTo(this.title, [], undefined, {
      features: {
        requestUri: true,
      },
    });
    defaultsTo(this.title, undefined, undefined, {
      features: {
        requestUri: {
          requireRequestUriRegistration: false,
        },
      },
    });
    mustBeArray(this.title);

    allows(this.title, ['https://a-web-uri']);
    rejects(this.title, [123], /must only contain strings$/);
    rejects(this.title, ['not a uri'], /must only contain https uris$/);
    rejects(this.title, ['custom-scheme://not-a-web-uri'], /must only contain https uris$/);
    rejects(this.title, ['http://a-web-uri'], /must only contain https uris$/);
  });

  context('web_message_uris', function () {
    const configuration = { features: { webMessageResponseMode: true } };
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
      allows(this.title, [value], {
        grant_types: ['implicit', 'authorization_code'],
      });
    });
    allows(this.title, responseTypes, {
      grant_types: ['implicit', 'authorization_code'],
    });
    allows(this.title, ['token id_token'], { // mixed up order
      grant_types: ['implicit'],
    }, undefined, (client) => {
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
        'tls_client_auth',
      ],
    };

    if (!endpointAuthMethodProperty.startsWith('token')) {
      Object.assign(configuration, {
        features: { [endpointAuthMethodProperty.split('_')[0]]: true },
      });
    }

    context(endpointAuthMethodProperty, function () {
      defaultsTo(this.title, 'client_secret_basic', undefined, configuration);
      mustBeString(this.title, undefined, undefined, configuration);

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
            allows(this.title, value, {
              tls_client_auth_subject_dn: 'foo',
            }, configuration);
            rejects(this.title, value, 'tls_client_auth_subject_dn must be provided for tls_client_auth', undefined, configuration);
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
      allows(this.title, 'RS256', {
        [endpointAuthMethodProperty]: 'client_secret_jwt',
      }, configuration);

      const confProperty = `${camelCase(endpointAuthSigningAlgProperty)}Values`;
      rejects(this.title, 'RS384', new RegExp(`^${endpointAuthSigningAlgProperty} must be one of`), {
        [endpointAuthMethodProperty]: 'client_secret_jwt',
      }, Object.assign({}, {
        whitelistedJWA: {
          [confProperty]: pull(cloneDeep(whitelistedJWA[confProperty]), 'RS384'),
        },
      }, configuration));
    });
  });

  context('userinfo_signed_response_alg', function () {
    defaultsTo(this.title, undefined);
    mustBeString(this.title);
    allows(this.title, 'HS256');
    rejects(this.title, 'not-an-alg');
  });

  context('introspection_signed_response_alg', function () {
    const configuration = { features: { introspection: true, jwtIntrospection: true } };
    defaultsTo(this.title, 'RS256', undefined, configuration);
    mustBeString(this.title, undefined, undefined, configuration);
    allows(this.title, 'HS256', undefined, configuration);
    rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
  });

  context('authorization_signed_response_alg', function () {
    const configuration = { features: { jwtResponseModes: true } };
    defaultsTo(this.title, 'RS256', undefined, configuration);
    mustBeString(this.title, undefined, undefined, configuration);
    allows(this.title, 'HS256', undefined, configuration);
    rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    rejects(this.title, 'none', undefined, undefined, configuration);
  });

  context('features.encryption', () => {
    const configuration = {
      features: {
        encryption: true, introspection: true, jwtIntrospection: true, jwtResponseModes: true,
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
      [
        'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].forEach((value) => {
        allows(this.title, value, {
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('id_token_encrypted_response_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, 'A128CBC-HS256', {
        id_token_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        id_token_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          id_token_encrypted_response_alg: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        id_token_encrypted_response_alg: 'RSA1_5',
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
      [
        'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].forEach((value) => {
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
        userinfo_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        userinfo_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          userinfo_encrypted_response_alg: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        userinfo_encrypted_response_alg: 'RSA1_5',
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
      [
        'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].forEach((value) => {
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
        introspection_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        introspection_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          introspection_encrypted_response_alg: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        introspection_encrypted_response_alg: 'RSA1_5',
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
      [
        'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW',
        'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'A128KW', 'A192KW', 'A256KW',
        'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
      ].forEach((value) => {
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
        authorization_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      mustBeString(this.title, undefined, {
        authorization_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          authorization_encrypted_response_alg: 'RSA1_5',
          jwks: { keys: [sigKey] },
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        authorization_encrypted_response_alg: 'RSA1_5',
        jwks: { keys: [sigKey] },
      }, configuration);
    });
  });

  describe('features.encryption & features.request', () => {
    const configuration = { features: { encryption: true, request: true } };
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
      [
        'RSA-OAEP', 'RSA1_5', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
      ].forEach((value) => {
        allows(this.title, value, undefined, configuration);
      });
      rejects(this.title, 'not-an-alg', undefined, undefined, configuration);
    });

    context('request_object_encryption_enc', function () {
      defaultsTo(this.title, undefined);
      defaultsTo(this.title, undefined, undefined, configuration);
      defaultsTo(this.title, 'A128CBC-HS256', {
        request_object_encryption_alg: 'RSA1_5',
      }, configuration);
      mustBeString(this.title, undefined, {
        request_object_encryption_alg: 'RSA1_5',
      }, configuration);
      [
        'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM',
      ].forEach((value) => {
        allows(this.title, value, {
          request_object_encryption_alg: 'RSA1_5',
        }, configuration);
      });
      rejects(this.title, 'not-an-enc', undefined, {
        request_object_encryption_alg: 'RSA1_5',
      }, configuration);
    });
  });

  context('jwks', function () {
    const configuration = {
      features: {
        introspection: true, jwtIntrospection: true, revocation: true, encryption: true,
      },
    };

    rejects(this.title, 'string', 'jwks must be a JWK Set');
    rejects(this.title, {}, 'jwks must be a JWK Set');
    rejects(this.title, 1, 'jwks must be a JWK Set');
    rejects(this.title, 0, 'jwks must be a JWK Set');
    rejects(this.title, true, 'jwks must be a JWK Set');
    rejects(this.title, { keys: [] }, 'jwks.keys must not be empty');
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

    const invalidx5c = cloneDeep(mtlsKeys);
    invalidx5c.keys[0].x5c = true;
    rejects(this.title, invalidx5c, 'when provided, JWK x5c must be non-empty an array');

    const emptyx5c = cloneDeep(mtlsKeys);
    emptyx5c.keys[0].x5c = [];
    rejects(this.title, emptyx5c, 'when provided, JWK x5c must be non-empty an array');

    const invalidCert = cloneDeep(mtlsKeys);
    invalidCert.keys[0].x5c = ['foobar'];
    rejects(this.title, invalidCert, 'invalid x5c provided');

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

  context('features.certificateBoundAccessTokens', () => {
    context('tls_client_certificate_bound_access_tokens', function () {
      const configuration = {
        features: {
          certificateBoundAccessTokens: true,
        },
      };

      defaultsTo(this.title, false, undefined, configuration);
      defaultsTo(this.title, undefined);
      mustBeBoolean(this.title, undefined, configuration);
    });
  });

  context('features.sessionManagement', () => {
    context('post_logout_redirect_uris', function () {
      const configuration = {
        features: {
          sessionManagement: true,
        },
      };

      defaultsTo(this.title, [], undefined, configuration);
      defaultsTo(this.title, undefined);
      mustBeArray(this.title, undefined, configuration);

      rejects(this.title, [123], /must only contain strings$/, undefined, configuration);
      allows(this.title, ['http://a-web-uri'], undefined, configuration);
      allows(this.title, ['https://a-web-uri'], undefined, configuration);
      allows(this.title, ['any-custom-scheme://not-a-web-uri'], undefined, configuration);
      rejects(this.title, ['not a uri'], /must only contain uris$/, undefined, configuration);
    });
  });

  context('features.backchannelLogout', () => {
    const configuration = {
      features: {
        backchannelLogout: true,
      },
    };

    context('post_logout_redirect_uris', function () {
      defaultsTo(this.title, [], undefined, configuration);
      defaultsTo(this.title, undefined);
      mustBeArray(this.title, undefined, configuration);

      rejects(this.title, [123], /must only contain strings$/, undefined, configuration);
      allows(this.title, ['http://a-web-uri'], undefined, configuration);
      allows(this.title, ['https://a-web-uri'], undefined, configuration);
      allows(this.title, ['any-custom-scheme://not-a-web-uri'], undefined, configuration);
      rejects(this.title, ['not a uri'], /must only contain uris$/, undefined, configuration);
    });

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

  context('features.frontchannelLogout', () => {
    const configuration = {
      features: {
        frontchannelLogout: true,
      },
    };

    context('post_logout_redirect_uris', function () {
      defaultsTo(this.title, [], undefined, configuration);
      defaultsTo(this.title, undefined);
      mustBeArray(this.title, undefined, configuration);

      rejects(this.title, [123], /must only contain strings$/, undefined, configuration);
      allows(this.title, ['http://a-web-uri'], undefined, configuration);
      allows(this.title, ['https://a-web-uri'], undefined, configuration);
      allows(this.title, ['any-custom-scheme://not-a-web-uri'], undefined, configuration);
      rejects(this.title, ['not a uri'], /must only contain uris$/, undefined, configuration);
    });

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
    features: { clientCredentials: true },
  }).then((client) => {
    expect(client.grantTypes).not.to.be.empty;
    expect(client.responseTypes).to.be.empty;
    expect(client.redirectUris).to.be.empty;
  }));
});
