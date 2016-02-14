'use strict';

let crypto = require('crypto');
let url = require('url');

let _ = require('lodash');
let compose = require('koa-compose');

let got = require('got');
let uuid = require('node-uuid');

let bodyMiddleware = require('../middlewares/selective_body');
let dupesMiddleware = require('../middlewares/check_dupes');
let paramsMiddleware = require('../middlewares/get_params');

let errors = require('../helpers/errors');
let formPost = require('../helpers/form_post');
let JWT = require('../helpers/jwt');
let redirectUri = require('../helpers/redirect_uri');

const RESPONSE_TYPES = {
  code: {
    flow: 'authorization_code',
    mode: 'query',
  },
  'code id_token': {
    flow: 'implicit',
    mode: 'fragment',
  },
  'code id_token token': {
    flow: 'implicit',
    mode: 'fragment',
  },
  'code token': {
    flow: 'hybrid',
    mode: 'fragment',
  },
  id_token: {
    flow: 'hybrid',
    mode: 'fragment',
  },
  'id_token token': {
    flow: 'hybrid',
    mode: 'fragment',
  },
  none: {
    mode: 'query',
  },
};

const PARAM_LIST = [
  'acr_values',
  'claims',
  'claims_locales',
  'client_id',
  'display',
  'id_token_hint',
  'login_hint',
  'max_age',
  'nonce',
  'prompt',
  'redirect_uri',
  'registration',
  'request',
  'request_uri',
  'response_mode',
  'response_type',
  'scope',
  'state',
  'ui_locales',
];

let body = bodyMiddleware({
  only: 'application/x-www-form-urlencoded',
  raise: true,
});

let getParams = paramsMiddleware({
  whitelist: PARAM_LIST,
});

let sessionOrigin = (uri) => {
  return url.format(Object.assign(url.parse(uri), {
    hash: null,
    pathname: null,
    search: null
  }));
};

module.exports = function(provider) {

  let conf = provider.configuration;

  let ClaimsMask = require('../helpers/claims_mask')(conf);

  let needed = _.chain(conf.responseTypesSupported).map((rt) => {
    return rt.split(' ');
  }).flatten().uniq().value();

  let handlers = {};

  if (needed.indexOf('token') !== -1) {
    handlers.token = function * () {
      let at = new provider.AccessToken({
        accountId: this.oidc.accountId,
        claims: this.oidc.claims,
        clientId: this.oidc.client.clientId,
        grantId: this.oidc.uuid,
        scope: this.oidc.params.scope,
      });

      return {
        access_token: yield at.toToken(),
        expires_in: provider.AccessToken.expiresIn,
        token_type: 'Bearer',
      };
    };
  }

  if (needed.indexOf('code') !== -1) {
    handlers.code = function * () {
      let ac = new provider.AuthorizationCode({
        accountId: this.oidc.accountId,
        acr: this.oidc.session.acr(this.oidc.uuid),
        authTime: this.oidc.session.authTime(),
        claims: this.oidc.claims,
        clientId: this.oidc.client.clientId,
        grantId: this.oidc.uuid,
        nonce: this.oidc.params.nonce,
        redirectUri: this.oidc.params.redirect_uri,
        scope: this.oidc.params.scope,
      });

      return {
        code: yield ac.toToken(),
      };
    };
  }

  if (needed.indexOf('id_token') !== -1) {
    handlers.id_token = function * () {
      let token = new provider.IdToken(
        Object.assign({}, this.oidc.account.claims(), {
          acr: this.oidc.session.acr(this.oidc.uuid),
          auth_time: this.oidc.session.authTime(),
        }), this.oidc.client.sectorIdentifier);

      token.scope = this.oidc.params.scope;
      token.mask = _.get(this.oidc.claims, 'id_token', {});
      token.extras = {
        nonce: this.oidc.params.nonce,
      };

      return {
        id_token: token,
      };
    };
  }

  if (needed.indexOf('none') !== -1) {
    handlers.none = function * () {
      return {};
    };
  }

  let loadClient = function * loadClient(clientId) {
    // Validate: client_id param
    let client = provider.Client.find(clientId);

    this.assert(client,
      new errors.InvalidRequestError('unrecognized client_id'));

    return client;

  };

  return compose([

    function * authorizationErrorHandler(next) {
      try {
        yield next;
      } catch (err) {

        let out = {};

        if (err.expose) {
          Object.assign(out, {
            error: err.message,
            error_description: err.error_description,
          });
        } else {
          Object.assign(out, {
            error: 'server_error',
            error_description: 'oops something went wrong',
          });
        }

        provider.emit(out.error === 'server_error' ?
          'server_error' : 'authentication.error', err, this);

        let params;
        params = this.oidc.params;
        params = params || (this.method === 'POST' ?
          this.request.body : this.query);

        if (params.state !== undefined) {
          out.state = params.state;
        }

        if (this.oidc.uuid) {
          // TODO: cleanup
        }

        // redirect uri error should render instead of redirect uri
        if (err.message === 'redirect_uri_mismatch' || !params.redirect_uri) {
          return provider.configuration.renderError.call(this, out);
        }

        if (params.response_mode === 'form_post') {
          formPost.call(this, out);
        } else {
          let uri = redirectUri(params.redirect_uri, out, params.response_mode);
          this.redirect(uri);
        }
      }
    },

    function * (next) {
      this.oidc.uuid = this.oidc.uuid || uuid.v4();
      yield next;
    },

    function * parseBody(next) {
      if (this.method === 'POST') {
        yield body.call(this, next);
      } else {
        yield next;
      }
    },

    getParams,

    dupesMiddleware,

    function * checkResponseMode(next) {
      // Validate: response_mode param
      let params = this.oidc.params;

      if (!params.response_mode !== undefined) {
        params.response_mode = _.get(RESPONSE_TYPES,
          `${params.response_type}.mode`, 'query');
        yield next;
        return;
      }

      let invalid = params.response_mode === 'query' &&
        params.response_type.includes('token');

      this.assert(!invalid, new errors.InvalidRequestError(
        'response_mode not allowed for this response_type'));

      yield next;
    },

    function * throwNotSupported(next) {
      let params = this.oidc.params;
      let feature = provider.configuration.features;

      if (!feature.request && params.request !== undefined) {
        this.throw(400, 'request_not_supported', {
          error_description: 'request parameter provided but not supported',
        });
      }

      if (!feature.requestUri && params.request_uri !== undefined) {
        this.throw(400, 'request_uri_not_supported', {
          error_description: 'request_uri parameter provided but not supported',
        });
      }

      if (!feature.selfIssued && params.registration !== undefined) {
        this.throw(400, 'registration_not_supported', {
          error_description:
            'registration parameter provided but not supported',
        });
      }

      this.assert(params.request === undefined ||
        params.request_uri === undefined, new errors.InvalidRequestError(
          'request and request_uri parameters MUST NOT be used together'));

      yield next;
    },

    function * fetchRequestUri(next) {
      let params = this.oidc.params;

      if (params.request_uri !== undefined) {
        this.assert(params.request_uri.length <= 512, 400,
          'invalid_request_uri', {
            error_description: 'the request_uri MUST NOT exceed 512 characters',
          });

        this.assert(params.request_uri.startsWith('https://'), 400,
          'invalid_request_uri', {
            error_description: 'request_uri must use https scheme',
          });

        let request;
        try {
          request = yield got(params.request_uri, {
            headers: {
              'User-Agent': provider.issuer,
            },
            timeout: 1500,
          });
        } catch (err) {
          this.throw(400, 'invalid_request_uri', {
            error_description:
              `could not load or parse request_uri (${err.message})`,
            });
        }

        delete params.request_uri;
        params.request = request.body;

      }

      yield next;
    },

    function * decodeRequest(next) {
      let params = this.oidc.params;

      if (params.request === undefined) {
        yield next;
        return;
      }

      let decoded;

      try {
        if (params.request.split('.').length > 3) {
          let decrypted = yield JWT.decrypt(params.request, provider.keystore);
          params.request = decrypted.payload.toString('utf8');
        }
        decoded = JWT.decode(params.request);
      } catch (err) {
        this.throw(400, 'invalid_request_object', {
            error_description:
              `could not parse request_uri as valid JWT (${err.message})`,
          });
      }

      this.assert(decoded,
        'could not parse request_uri as valid JWT');

      let payload = decoded.payload;

      this.assert(payload.request === undefined ||
        payload.request_uri === undefined, 400, 'invalid_request_object', {
          error_description:
            'request object must not contain request or request_uri properties',
        });

      payload = _.pick(payload, PARAM_LIST);

      this.assert(payload.response_type === undefined ||
        payload.response_type === params.response_type, 400,
          'invalid_request_object', {
            error_description:
              'request response_type must equal the one in request parameters',
          });

      this.assert(payload.client_id === undefined ||
        payload.client_id === params.client_id, 400, 'invalid_request_object', {
          error_description:
            'request client_id must equal the one in request parameters',
        });

      let client = yield loadClient.call(this, params.client_id);

      let alg = decoded.header.alg;

      if (client.request_object_signing_alg) {
        this.assert(client.request_object_signing_alg === alg, 400,
          'invalid_request_object', {
            error_description:
              'the preregistered alg must be used in request or request_uri',
          });
      }

      if (alg !== 'none') {
        try {
          yield client.keystore.refresh();
          yield JWT.verify(params.request, client.keystore);
        } catch (err) {
          this.throw(400, 'invalid_request_object', {
              error_description:
                `could not validate request object signature (${err.message})`,
            });
        }
      }

      Object.assign(params, payload);
      delete params.request;

      // TODO: params.scope must contain openid too
      this.oidc.client = client;

      yield next;
    },

    function * checkRequired(next) {
      // Validate: required params
      let params = this.oidc.params;
      let missing = _.difference([
        'response_type',
        'client_id',
        'scope',
        'redirect_uri',
      ], _.keys(params));

      // Second check for nonce if id_token is involved
      if (params.response_type && !params.nonce &&
          params.response_type.includes('id_token')) {
        missing.push('nonce');
      }

      this.assert(_.isEmpty(missing), new errors.InvalidRequestError(
        `missing required parameter(s) ${missing.join(',')}`));

      yield next;
    },

    function * checkPrompt(next) {
      // Validate: prompt

      let prompts;

      if (this.oidc.params.prompt !== undefined) {
        prompts = this.oidc.params.prompt.split(' ');
        let unsupported = _.difference(prompts, provider.configuration.prompts);

        this.assert(_.isEmpty(unsupported), new errors.InvalidRequestError(
          `invalid prompt value(s) provided. (${unsupported.join(',')})`));

        this.assert(prompts.indexOf('none') === -1 || prompts.length === 1,
          new errors.InvalidRequestError(
            'prompt none must only be used alone'));
      }

      this.oidc.prompts = prompts || [];

      yield next;
    },

    function * definePrompt(next) {
      let oidc = this.oidc;

      oidc.prompt = (prompt) => {
        if (oidc.result) {
          switch (prompt) {
          case 'none':
            return true;
          default:
            let should = _.difference(oidc.prompts, _.keys(oidc.result));
            return should.indexOf(prompt) !== -1;
          }
        } else {
          return oidc.prompts.indexOf(prompt) !== -1;
        }
      };

      yield next;
    },

    function * checkScope(next) {
      let scopes = this.oidc.params.scope.split(' ');

      // Validate: only supported scopes
      let unsupported = _.difference(scopes, provider.configuration.scopes);
      this.assert(_.isEmpty(unsupported), new errors.InvalidRequestError(
        `invalid scope value(s) provided. (${unsupported.join(',')})`));

      // Validate: openid scope is present
      this.assert(scopes.indexOf('openid') !== -1,
        new errors.InvalidRequestError('openid is required scope'));

      this.assert(
        scopes.indexOf('offline_access') === -1 || this.oidc.prompt('consent'),
          new errors.InvalidRequestError(
            'offline_access scope requires consent prompt'));

      this.oidc.scopes = scopes;

      yield next;
    },

    function * checkClient(next) {
      let oidc = this.oidc;

      // Validate: client_id param
      if (!oidc.client) {
        oidc.client = yield loadClient.call(this, oidc.params.client_id);
      }

      yield next;
    },

    function * checkResponseType(next) {
      // Validate: response_type param
      let params = this.oidc.params;
      let supported = provider.configuration.responseTypesSupported;

      let valid = supported.indexOf(params.response_type) !== -1;
      this.assert(valid, 400, 'unsupported_response_type', {
        error_description:
          `response_type not supported. (${params.response_type})`,
      });

      this.assert(this.oidc.client.responseTypeAllowed(params.response_type),
        400, 'restricted_response_type', {
          error_description: 'response_type not allowed for this client',
        });

      this.oidc.flow = RESPONSE_TYPES[params.response_type].flow;

      yield next;
    },

    function * checkRedirectUri(next) {
      // Validate: redirect_uri param

      this.assert(
        this.oidc.client.redirectUriAllowed(this.oidc.params.redirect_uri),
          new errors.RedirectUriMismatchError());

      // TODO: if flow=authorization_code MAY use the http scheme, provided that
      //  the Client Type is confidential, as defined in Section 2.1 of OAuth
      //  2.0,
      // TODO: The Redirection URI MAY use an alternate scheme, such as one that
      // is intended to identify a callback into a native application.

      // TODO: if Implicit. MUST NOT be 'http' unless application_type = native,
      // in which case it MAY use the http: scheme with localhost as the
      //  hostname.

      // HYBRID - same as code

      yield next;
    },

    function * assignDefaults(next) {

      let params = this.oidc.params;
      let client = this.oidc.client;

      if (!params.acr_values && client.defaultAcrValues) {
        params.acr_values = client.defaultAcrValues.join(' ');
      }

      if (!params.max_age && client.defaultMaxAge) {
        params.max_age = client.defaultMaxAge;
      }

      yield next;
    },

    function * checkClaims(next) {
      // Validate: claims param

      let params = this.oidc.params;

      // Assert response_type !none !id_token
      if (provider.configuration.features.claimsParameter &&
        params.claims !== undefined) {

        this.assert(params.response_type !== 'none',
          new errors.InvalidRequestError(
            'claims parameter should not be combined with response_type none'));

        let claims;

        try {
          claims = JSON.parse(params.claims);
        } catch (err) {
          this.throw(new errors.InvalidRequestError(
            'could not parse the claims parameter JSON'));
        }

        this.assert(_.isPlainObject(claims),
          new errors.InvalidRequestError(
            'claims parameter should be a JSON object'));

        this.assert(claims.userinfo !== undefined ||
          claims.id_token !== undefined, new errors.InvalidRequestError(
            'claims parameter should have userinfo or id_token properties'));

        this.assert(!claims.userinfo !== undefined ||
          _.isPlainObject(claims.userinfo), new errors.InvalidRequestError(
            'claims.userinfo should be an object'));

        this.assert(!claims.id_token !== undefined ||
          _.isPlainObject(claims.id_token), new errors.InvalidRequestError(
            'claims.id_token should be an object'));

        this.assert(params.response_type !== 'id_token' ||
          !claims.userinfo, new errors.InvalidRequestError(
            'claims.userinfo should not be used if access_token is not issued'
          ));

        this.oidc.claims = claims;
      }

      if (params.max_age || this.oidc.client.requireAuthTime) {
        this.oidc.claims = this.oidc.claims || {};
        _.merge(this.oidc.claims, {
          id_token: {
            auth_time: {
              essential: true,
            },
          },
        });
      }

      let acrValues = params.acr_values;

      if (acrValues) {
        this.oidc.claims = this.oidc.claims || {};
        _.merge(this.oidc.claims, {
          id_token: {
            acr: {
              values: Array.isArray(acrValues) ?
                acrValues : acrValues.split(' '),
            },
          },
        });
      }

      yield next;
    },

    function * loadAccount(next) {
      let account;
      let accountId = this.oidc.session.accountId();

      if (accountId) {
        account = yield provider.Account.findById(accountId);
      }

      this.oidc.accountId = accountId;
      this.oidc.account = account;


      yield next;
    },

    function * interactions(next) {
      // Validate: login required

      let clientName = _.get(this.oidc.client, 'name', 'Client');

      let loginInteractions = [

        // no account id was found in the session info
        () => {
          if (!this.oidc.accountId) {
            return {
              error: 'login_required',
              error_description: 'End-User authentication is required',
              reason: 'no_session',
              reason_description: 'Please Sign-in to continue.',
            };
          }
        },

        // login was requested by the client by prompt parameter
        () => {
          if (this.oidc.prompt('login')) {
            return {
              error: 'login_required',
              error_description:
                'End-User authentication could not be obtained',
              reason: 'login_prompt',
              reason_description: `${clientName} asks you to Sign-in again.`,
            };
          }
        },

        // session is too old for this authentication request
        () => {
          if (this.oidc.session.past(this.oidc.params.max_age)) {
            return {
              error: 'login_required',
              error_description:
                'End-User re-authentication could not be obtained',
              reason: 'max_age',
              reason_description: `${clientName} asks you to Sign-in again.`,
            };
          }
        },

        // session subject value differs from the one requested
        () => {
          if (_.has(this.oidc.claims, 'id_token.sub.value')) {
            let actualSub = ClaimsMask.sub(this.oidc.accountId,
              this.oidc.client.sectorIdentifier);
            if (this.oidc.claims.id_token.sub.value !== actualSub) {
              return {
                error: 'login_required',
                error_description: 'requested subject could not be obtained',
                reason: 'claims_id_token_sub_value',
                reason_description:
                  `${clientName} asks you to Sign-in with a specific identity.`,
              };
            }
          }
        },

        // none of multiple authentication context class references requested
        // are met
        () => {
          let requestedAcr;
          if (
            _.get(this.oidc.claims, 'id_token.acr.essential') &&
            (requestedAcr = _.get(this.oidc.claims, 'id_token.acr.values'))
          ) {
            if (requestedAcr.indexOf(this.oidc.session.acr()) === -1 ) {
              return {
                error: 'login_required',
                error_description:
                  'none of the requested ACRs could not be obtained',
                reason: 'essential_acrs',
                reason_description:
                  `${clientName} asks you to Sign-in using a specific method.`,
              };
            }
          }
        },

        // single requested authentication context class reference is not met
        () => {
          let requestedAcr;
          if (
            _.get(this.oidc.claims, 'id_token.acr.essential') &&
            (requestedAcr = _.get(this.oidc.claims, 'id_token.acr.value'))
          ) {
            if (requestedAcr !== this.oidc.session.acr()) {
              return {
                error: 'login_required',
                error_description: 'requested ACR could not be obtained',
                reason: 'essential_acr',
                reason_description:
                  `${clientName} asks you to Sign-in using a specific method.`,
              };
            }
          }
        },
      ];

      let interaction;

      _.forEach(loginInteractions, (fn) => {
        if ((interaction = fn())) {
          return false;
        }
      });

      if (!interaction && this.oidc.params.id_token_hint !== undefined) {
        let decoded;
        let actualSub = ClaimsMask.sub(this.oidc.accountId,
          this.oidc.client.sectorIdentifier);

        try {
          decoded = yield provider.IdToken.validate(
            this.oidc.params.id_token_hint, this.oidc.client);
          decoded = decoded.payload;
        } catch (err) {
          this.throw(new errors.InvalidRequestError(
            'could not validate id_token_hint'));
        }

        if (decoded.sub !== actualSub) {
          interaction = {
            error: 'login_required',
            error_description:
              'id_token_hint and authenticated subject do not match',
            reason: 'id_token_hint',
            reason_description:
              `${clientName} asks that you Sign-in with a specific identity.`,
          };
        }
      }

      if (interaction) {

        _.defaults(interaction, {
          error: 'interaction_required',
          error_description: 'interaction is required from the end-user',
        });

        // If login but prompt(none) throw;
        this.assert(!this.oidc.prompt('none'), 302, interaction.error, {
          error_description: interaction.error_description,
        });

        let interactionPath = provider.configuration.interactionPath(
          this.oidc.uuid);

        let j = JSON.stringify;

        this.cookies.set('_grant', j({
          details: interaction,
          params: this.oidc.params,
        }), Object.assign({
          path: interactionPath,
        }, provider.configuration.cookies.short));

        this.cookies.set('_grant', j(this.oidc.params), Object.assign({
          path: this.oidc.pathFor('respond', {
            grant: this.oidc.uuid,
          }),
        }, provider.configuration.cookies.short));

        return this.redirect(interactionPath);
      }

      yield next;
    },

    function * respond(next) {
      let out = yield next;

      if (this.oidc.params.state !== undefined) {
        out.state = this.oidc.params.state;
      }

      provider.emit('authentication.success', this);

      if (provider.configuration.features.sessionManagement) {
        let statesCookieName = '_session_states';
        let salt = crypto.randomBytes(8).toString('hex');
        let state = String(this.oidc.session.authTime());

        let shasum = crypto.createHash('sha256')
          .update(this.oidc.params.client_id)
          .update(' ')
          .update(sessionOrigin(this.oidc.params.redirect_uri))
          .update(' ')
          .update(state)
          .update(' ')
          .update(salt);

        let sessionStr = shasum.digest('hex');
        let states = {};
        try {
          Object.assign(states, JSON.parse(this.cookies.get(statesCookieName, {
            signed: provider.configuration.cookies.long.signed
          })));
        } catch (err) {}

        states[this.oidc.params.client_id] = state;

        this.cookies.set(statesCookieName, JSON.stringify(states),
          Object.assign({}, provider.configuration.cookies.long, {
            httpOnly: false
          }));

        out.session_state = `${sessionStr}.${salt}`;
      }

      if (this.oidc.params.response_mode === 'form_post') {
        formPost.call(this, this.oidc.params.redirect_uri, out);
      } else {
        let uri = redirectUri(this.oidc.params.redirect_uri, out,
          this.oidc.params.response_mode);
        this.redirect(uri);
      }
    },

    function * handleSuccess() {
      let responses = this.oidc.params.response_type.split(' ');
      let out = Object.assign.apply({}, yield responses.map((rt) => {
        return handlers[rt];
      }));

      if (out.access_token && out.id_token) {
        out.id_token.extra = {
          at_hash: out.access_token,
        };
      }

      if (out.code && out.id_token) {
        out.id_token.extra = {
          c_hash: out.code,
        };
      }

      if (out.id_token) {
        out.id_token = yield out.id_token.toJWT(this.oidc.client);
      }

      return out;
    },
  ]);
};
