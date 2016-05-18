/* eslint-disable newline-per-chained-call */
'use strict';

const _ = require('lodash');
const Joi = require('joi');
const url = require('url');
const jose = require('node-jose');
const assert = require('assert');
const base64url = require('base64url');
const got = require('got');

const errors = require('../helpers/errors');
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y'];

const KEY_TYPES = ['RSA', 'EC'];
const RECOGNIZED_METADATA = [
  'application_type',
  'client_id',
  'client_name',
  'client_secret',
  'client_secret_expires_at',
  'client_uri',
  'contacts',
  'default_acr_values',
  'default_max_age',
  'grant_types',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'post_logout_redirect_uris',
  'redirect_uris',
  'registration_access_token',
  'request_object_encryption_alg',
  'request_object_encryption_enc',
  'request_object_signing_alg',
  'request_uris',
  'require_auth_time',
  'response_types',
  'sector_identifier_uri',
  'subject_type',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
];

// TODO: validate all

module.exports = function getClient(provider) {
  const webUri = Joi.string().uri({
    scheme: ['http', 'https'],
  });

  function presenceDependant(field, value) {
    return (client) => {
      if (_.isUndefined(client[field])) {
        return undefined;
      }
      return value;
    };
  }

  function baseSchema() {
    const conf = provider.configuration;
    return Joi.object().keys({
      application_type: Joi.string().valid('web', 'native').default('web'),
      client_id: Joi.string().required(),
      client_name: Joi.string(),
      // TODO: validate secret length
      client_secret: Joi.string().required(),
      client_uri: webUri,
      contacts: Joi.array().items(Joi.string().email()),
      default_acr_values: Joi.array().items(Joi.string()),
      default_max_age: Joi.number().integer().positive().strict(),
      grant_types: Joi.array().min(1).items(conf.grantTypes)
        .default(['authorization_code']),
      id_token_signed_response_alg: Joi.string().when('response_types', {
        is: Joi.array().items(Joi.string().regex(/token/).forbidden()),
        then: Joi.string().valid(
          conf.idTokenSigningAlgValues),
        otherwise: Joi.string().valid(_.without(
          conf.idTokenSigningAlgValues, 'none')),
      }).default('RS256'),
      initiate_login_uri: webUri,
      redirect_uris: Joi.array().min(1).items(
        Joi.string().regex(/#/).forbidden()).when('application_type', {
          is: 'web',
          then: Joi.array().items(webUri),
          otherwise: Joi.array().items(Joi.string().uri()),
        }).required(),
      jwks_uri: webUri,
      logo_uri: webUri,
      policy_uri: webUri,
      post_logout_redirect_uris: Joi.array().items(webUri).default([]),
      request_object_signing_alg: Joi.string(
        conf.requestObjectSigningAlgValues),
      require_auth_time: Joi.boolean().default(false),
      response_types: Joi.array().min(1).items(conf.responseTypes)
        .default(['code']),
      sector_identifier_uri: Joi.string().uri({
        scheme: ['https'],
      }),
      subject_type: Joi.string().valid(conf.subjectTypes)
        .default('public'),
      token_endpoint_auth_method: Joi.string().valid(
        conf.tokenEndpointAuthMethods).default('client_secret_basic'),
      tos_uri: webUri,
      userinfo_signed_response_alg: Joi.string().valid(
        conf.userinfoSigningAlgValues).default('none'),
      id_token_encrypted_response_alg: Joi.string()
        .valid(conf.idTokenEncryptionAlgValues).default(undefined),
      id_token_encrypted_response_enc: Joi.string()
        .valid(conf.idTokenEncryptionEncValues)
          .default(presenceDependant(
            'id_token_encrypted_response_alg', 'A128CBC-HS256'),
            'id_token_encrypted_response_alg dependant default'),
      userinfo_encrypted_response_alg: Joi.string()
        .valid(conf.userinfoEncryptionAlgValues).default(undefined),
      userinfo_encrypted_response_enc: Joi.string()
        .valid(conf.userinfoEncryptionEncValues)
          .default(presenceDependant(
            'userinfo_encrypted_response_alg', 'A128CBC-HS256'),
            'userinfo_encrypted_response_alg dependant default'),
    })
    .with('id_token_encrypted_response_enc', 'id_token_encrypted_response_alg')
    .with('userinfo_encrypted_response_enc', 'userinfo_encrypted_response_alg')
    .unknown();
  }

  function schemaValidate(meta) {
    let metadata = meta;
    let schema = baseSchema();

    try {
      const signingAlg = metadata.request_object_signing_alg;
      const requireJwks =
        metadata.token_endpoint_auth_method === 'private_key_jwt' ||
        (signingAlg && signingAlg.startsWith('RS')) ||
        (signingAlg && signingAlg.startsWith('ES'));

      if (requireJwks) {
        schema = schema.or('jwks', 'jwks_uri');
      }

      metadata = Joi.attempt(_.chain(metadata).omitBy(_.isNull)
        .pick(RECOGNIZED_METADATA).value(), schema);

      const rts = _.chain(metadata.response_types).map(rt => rt.split(' '))
        .flatten().uniq().value();

      if (_.includes(rts, 'code')) {
        Joi.assert(metadata.grant_types,
          Joi.array().items(
            Joi.string().valid('authorization_code').required(),
            Joi.string()));
      }

      if (_.includes(rts, 'token') || _.includes(rts, 'id_token')) {
        Joi.assert(metadata.grant_types,
          Joi.array().items(
            Joi.string().valid('implicit').required(),
            Joi.string()));
      }

      if (metadata.subject_type === 'pairwise' &&
        !metadata.sector_identifier_uri) {
        const hosts = _.chain(metadata.redirect_uris)
          .map(uri => url.parse(uri).host).uniq().value();

        if (hosts.length === 1) {
          metadata.sector_identifier = hosts[0];
        } else {
          throw new Error('sector_identifier_uri is required when using ' +
            'multiple hosts in your redirect_uris');
        }
      } else if (metadata.sector_identifier_uri) {
        metadata.sector_identifier =
          url.parse(metadata.sector_identifier_uri).host;
      }

      return Promise.resolve(metadata);
    } catch (err) {
      const redirectUriError = err.details && err.details.length === 1 &&
        err.details[0].path.startsWith('redirect_uri');

      const message = _.map(err.details,
        member => `Validation error '${member.message}' in path '${member.path}'`).join('. ');
      return Promise.reject(new errors.InvalidClientMetadata(
        message || err.message, redirectUriError ?
          'invalid_redirect_uri' : undefined));
    }
  }

  function sectorValidate(metadata) {
    if (metadata.sector_identifier_uri !== undefined) {
      return got(metadata.sector_identifier_uri, {
        headers: {
          'User-Agent': provider.issuer,
        },
        json: true,
        timeout: 1500,
      }).then(response => {
        try {
          assert(Array.isArray(response.body),
            'sector_identifier_uri must return single JSON array');
          const missing = metadata.redirect_uris.find((uri) => response.body.indexOf(uri) === -1);
          assert(!missing,
            'all redirect_uris must be included in the sector_identifier_uri');
        } catch (err) {
          throw new errors.InvalidClientMetadata(err.message);
        }

        return metadata;
      }, (error) => {
        throw new errors.InvalidClientMetadata(
          `could not load sector_identifier_uri (${error.message})`);
      });
    }

    return metadata;
  }

  function buildClient(metadata) {
    const client = new Client(); // eslint-disable-line no-use-before-define

    Object.defineProperty(client, 'sectorIdentifier', {
      enumerable: false,
      writable: true,
    });

    Object.assign(client, _.mapKeys(metadata, (value, key) => _.camelCase(key)));

    return client;
  }

  function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', { value: jose.JWK.createKeyStore() });
    client.keystore.jwksUri = client.jwksUri;

    client.keystore.refresh = function refreshKeyStore() {
      if (!this.jwksUri) {
        return Promise.resolve();
      }

      return got(this.jwksUri, {
        headers: {
          'User-Agent': provider.issuer,
        },
        json: true,
        timeout: 1500,
      }).then((response) => {
        if (!Array.isArray(response.body.keys)) {
          throw new Error('invalid jwks_uri response');
        }

        const promises = [];

        response.body.keys.forEach((key) => {
          if (KEY_TYPES.indexOf(key.kty) !== -1 && !this.get(key.kid)) {
            promises.push(this.add(_.pick(key, KEY_ATTRIBUTES)));
          }
        });

        return Promise.all(promises);
      });
    };

    const promises = [];

    if (client.jwks && client.jwks.keys) {
      client.jwks.keys.forEach((key) => {
        if (KEY_TYPES.indexOf(key.kty) !== -1) {
          promises.push(client.keystore.add(_.pick(key, KEY_ATTRIBUTES)));
        }
      });
    }

    // TODO: DRY the adding of keys;

    return Promise.all(promises).then(() => {
      if (client.clientSecret) {
        return client.keystore.add({
          k: base64url(new Buffer(client.clientSecret)),
          kid: 'clientSecret',
          kty: 'oct',
        });
      }
      return Promise.resolve();
    }).then(() => client);
  }

  function register(client) {
    client.constructor.clients = client.constructor.clients || {};
    client.constructor.clients[client.clientId] = client;

    return client;
  }

  class Client {
    // (x) applicationType IN web,native
    // (x) grantTypes IN provider.configuration.grant_types_supported
    // (x) idTokenSignedResponseAlg IN
    //    provider.configuration.idTokenSignedResponseAlgSupported
    // (x) idTokenSignedResponseAlg MAY be 'none' if response_types does not
    //    contain any implicit or hybrid.
    // (x) requireAuthTime IN true/false
    // (x) responseTypes IN provider.configuration.responseTypes
    // (x) tokenEndpointAuthMethod IN
    //    client_secret_basic,client_secret_jwt,
    //    client_secret_post,private_key_jwt
    // (x) userinfoSignedResponseAlg IN
    //    provider.configuration.userinfoSigningAlgValues
    // (x) redirectUris are uris (http/https), option for strict https only?,
    //    native localhost?
    // (x) redirectUri does not have fragment
    // (x) contacts are emails
    // (x) clientName is String
    // (x) logoUri, clientUri, policyUri, tosUri, jwksUri
    // (x) sectorIdentifierUri
    // (x) subjectType IN pairwise,public and is it supported?
    // (x) defaultMaxAge +number of seconds
    // (x) defaultAcrValues
    // ( ) initiateLoginUri

    responseTypeAllowed(type) {
      return this.responseTypes.indexOf(type) !== -1;
    }

    grantTypeAllowed(type) {
      return this.grantTypes.indexOf(type) !== -1;
    }

    redirectUriAllowed(uri) {
      return this.redirectUris.indexOf(uri) !== -1;
    }

    postLogoutRedirectUriAllowed(uri) {
      return this.postLogoutRedirectUris.indexOf(uri) !== -1;
    }

    static add(metadata) {
      return schemaValidate(metadata)
        .then(sectorValidate)
        .then(buildClient)
        .then(buildKeyStore)
        .then(register);
    }

    static remove(id) {
      this.clients = this.clients || {};
      delete this.clients[id];
    }

    static find(id) {
      this.clients = this.clients || {};
      return this.clients[id];
    }

  }

  return Client;
};
