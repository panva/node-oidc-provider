'use strict';

const crypto = require('crypto');
const url = require('url');

const _ = require('lodash');
const compose = require('koa-compose');

const bodyParser = require('../middlewares/conditional_body');
const rejectDupes = require('../middlewares/check_dupes');
const paramsMiddleware = require('../middlewares/get_params');

const errors = require('../helpers/errors');
const mask = require('../helpers/claims');
const RequestUriCache = require('../helpers/request_uri_cache');
const formPost = require('../helpers/form_post');
const JWT = require('../helpers/jwt');
const redirectUri = require('../helpers/redirect_uri');

const j = JSON.stringify;

const RESPONSE_MODES = {
  'code id_token token': 'fragment',
  'code id_token': 'fragment',
  'code token': 'fragment',
  code: 'query',
  'id_token token': 'fragment',
  id_token: 'fragment',
  none: 'query',
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

const parseBody = bodyParser('application/x-www-form-urlencoded');
const getParams = paramsMiddleware(PARAM_LIST);

function sessionOrigin(uri) {
  return url.format(Object.assign(url.parse(uri), {
    hash: null,
    pathname: null,
    search: null,
  }));
}

module.exports = function authorizationAction(provider) {
  const conf = provider.configuration();
  const cache = new RequestUriCache(provider);
  const Claims = mask(conf);

  const needed = _.chain(conf.responseTypes)
    .map((rt) => rt.split(' '))
    .flatten()
    .uniq()
    .value();

  const handlers = {};

  if (needed.indexOf('token') !== -1) {
    handlers.token = function * tokenHandler() {
      const AccessToken = provider.get('AccessToken');
      const at = new AccessToken({
        accountId: this.oidc.session.accountId(),
        claims: this.oidc.claims,
        clientId: this.oidc.client.clientId,
        grantId: this.oidc.uuid,
        scope: this.oidc.params.scope,
      });

      return {
        access_token: yield at.save(),
        expires_in: AccessToken.expiresIn,
        token_type: 'Bearer',
      };
    };
  }

  if (needed.indexOf('code') !== -1) {
    handlers.code = function * codeHandler() {
      const AuthorizationCode = provider.get('AuthorizationCode');
      const ac = new AuthorizationCode({
        accountId: this.oidc.session.accountId(),
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
        code: yield ac.save(),
      };
    };
  }

  if (needed.indexOf('id_token') !== -1) {
    handlers.id_token = function idTokenHandler() {
      const IdToken = provider.get('IdToken');
      const token = new IdToken(
        Object.assign({}, this.oidc.account.claims(), {
          acr: this.oidc.session.acr(this.oidc.uuid),
          auth_time: this.oidc.session.authTime(),
        }), this.oidc.client.sectorIdentifier);

      token.scope = this.oidc.params.scope;
      token.mask = _.get(this.oidc.claims, 'id_token', {});

      token.set('nonce', this.oidc.params.nonce);

      return { id_token: token };
    };
  }

  if (needed.indexOf('none') !== -1) {
    handlers.none = function noneHandler() {
      return {};
    };
  }

  function * loadClient(clientId) {
    // Validate: client_id param
    this.assert(clientId, new errors.InvalidRequestError('missing required parameter client_id'));

    const Client = provider.get('Client');
    const client = yield Client.find(String(clientId));

    this.assert(client, new errors.InvalidClientError());

    return client;
  }

  return compose([

    parseBody,

    getParams,

    function * checkClient(next) {
      // Validate: client_id param
      this.oidc.client = yield loadClient.call(this, this.oidc.params.client_id);

      yield next;
    },

    rejectDupes,

    function * checkResponseMode(next) {
      // Validate: response_mode param
      const params = this.oidc.params;

      if (params.response_mode === undefined) {
        params.response_mode = _.get(RESPONSE_MODES, params.response_type, 'query');
        yield next;
        return;
      }

      const invalid = params.response_mode === 'query' && params.response_type.includes('token');

      this.assert(!invalid, new errors.InvalidRequestError(
        'response_mode not allowed for this response_type'));

      yield next;
    },

    function * throwNotSupported(next) {
      const params = this.oidc.params;
      const feature = provider.configuration('features');

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

      if (params.registration !== undefined) {
        this.throw(400, 'registration_not_supported', {
          error_description: 'registration parameter provided but not supported',
        });
      }

      this.assert(params.request === undefined ||
        params.request_uri === undefined, new errors.InvalidRequestError(
          'request and request_uri parameters MUST NOT be used together'));

      yield next;
    },

    function * OAuthRequired(next) {
      // Validate: required oauth params
      const params = this.oidc.params;
      const missing = _.difference([
        'response_type',
        'client_id',
        'scope',
      ], _.keys(_.omitBy(params, _.isUndefined)));

      this.assert(_.isEmpty(missing), new errors.InvalidRequestError(
        `missing required parameter(s) ${missing.join(',')}`));

      yield next;
    },

    function * checkOpenIdPresent(next) {
      const scopes = this.oidc.params.scope.split(' ');

      // Validate: openid scope is present
      this.assert(scopes.indexOf('openid') !== -1,
        new errors.InvalidRequestError('openid is required scope'));

      yield next;
    },

    function * noRedirectUriClients(next) {
      const oidc = this.oidc;
      // Validate: client_id param
      if (oidc.params.redirect_uri === undefined && oidc.client.redirectUris.length === 1) {
        oidc.params.redirect_uri = oidc.client.redirectUris[0];
      }

      yield next;
    },

    function * fetchRequestUri(next) {
      const params = this.oidc.params;

      if (params.request_uri !== undefined) {
        this.assert(params.request_uri.length <= 512, 400,
          'invalid_request_uri', {
            error_description: 'the request_uri MUST NOT exceed 512 characters',
          });

        this.assert(params.request_uri.startsWith('https://'), 400,
          'invalid_request_uri', {
            error_description: 'request_uri must use https scheme',
          });

        if (this.oidc.client.requestUris) {
          this.assert(this.oidc.client.requestUriAllowed(params.request_uri),
            400, 'invalid_request_uri', {
              error_description: 'not registered request_uri provided',
            });
        }

        try {
          params.request = yield cache.resolve(params.request_uri);
          params.request_uri = undefined;
        } catch (err) {
          this.throw(400, 'invalid_request_uri', {
            error_description: `could not load or parse request_uri (${err.message})`,
          });
        }
      }

      yield next;
    },

    function * decodeRequest(next) {
      const params = this.oidc.params;

      if (params.request === undefined) {
        yield next;
        return;
      }

      let decoded;

      try {
        if (provider.configuration('features.encryption') &&
          params.request.split('.').length === 5) {
          const decrypted = yield JWT.decrypt(params.request, provider.keystore);
          params.request = decrypted.payload.toString('utf8');
        }
        decoded = JWT.decode(params.request);
      } catch (err) {
        this.throw(400, 'invalid_request_object', {
          error_description: `could not parse request_uri as valid JWT (${err.message})`,
        });
      }

      this.assert(decoded, 'could not parse request_uri as valid JWT');

      let payload = decoded.payload;

      this.assert(payload.request === undefined &&
        payload.request_uri === undefined, 400, 'invalid_request_object', {
          error_description: 'request object must not contain request or request_uri properties',
        });

      payload = _.pick(payload, PARAM_LIST);

      this.assert(payload.response_type === undefined ||
        payload.response_type === params.response_type, 400,
          'invalid_request_object', {
            error_description: 'request response_type must equal the one in request parameters',
          });

      this.assert(payload.client_id === undefined ||
        payload.client_id === params.client_id, 400, 'invalid_request_object', {
          error_description: 'request client_id must equal the one in request parameters',
        });

      const client = this.oidc.client;
      const alg = decoded.header.alg;

      if (client.requestObjectSigningAlg) {
        this.assert(client.requestObjectSigningAlg === alg, 400,
          'invalid_request_object', {
            error_description: 'the preregistered alg must be used in request or request_uri',
          });
      }

      if (alg !== 'none') {
        try {
          yield JWT.verify(params.request, client.keystore);
        } catch (err) {
          this.throw(400, 'invalid_request_object', {
            error_description: `could not validate request object signature (${err.message})`,
          });
        }
      }

      Object.assign(params, payload);
      params.request = undefined;

      yield next;
    },

    function * OIDCRequired(next) {
      // Validate: required params
      const params = this.oidc.params;
      const missing = [];

      if (params.redirect_uri === undefined) missing.push('redirect_uri');

      // Second check for nonce if id_token is involved
      if (params.response_type && !params.nonce && params.response_type.includes('id_token')) {
        missing.push('nonce');
      }

      this.assert(_.isEmpty(missing), new errors.InvalidRequestError(
        `missing required parameter(s) ${missing.join(',')}`));

      yield next;
    },

    function * checkPrompt(next) {
      // Validate: prompt

      if (this.oidc.params.prompt !== undefined) {
        const prompts = this.oidc.prompts;
        const unsupported = _.difference(prompts, provider.configuration('prompts'));

        this.assert(_.isEmpty(unsupported), new errors.InvalidRequestError(
          `invalid prompt value(s) provided. (${unsupported.join(',')})`));

        this.assert(prompts.indexOf('none') === -1 || prompts.length === 1,
          new errors.InvalidRequestError('prompt none must only be used alone'));
      }

      yield next;
    },

    function * checkScope(next) {
      const scopes = this.oidc.params.scope.split(' ');

      // Validate: only supported scopes
      const unsupported = _.difference(scopes, provider.configuration('scopes'));
      this.assert(_.isEmpty(unsupported), new errors.InvalidRequestError(
        `invalid scope value(s) provided. (${unsupported.join(',')})`));

      // Validate: openid scope is present
      this.assert(scopes.indexOf('openid') !== -1,
        new errors.InvalidRequestError('openid is required scope'));

      if (scopes.indexOf('offline_access') !== -1 && this.oidc.prompts.indexOf('consent') === -1) {
        this.throw(new errors.InvalidRequestError('offline_access scope requires consent prompt'));
      }

      yield next;
    },

    function * checkResponseType(next) {
      // Validate: response_type param
      const params = this.oidc.params;
      const supported = provider.configuration('responseTypes');

      const valid = supported.indexOf(params.response_type) !== -1;
      this.assert(valid, 400, 'unsupported_response_type', {
        error_description: `response_type not supported. (${params.response_type})`,
      });

      this.assert(this.oidc.client.responseTypeAllowed(params.response_type),
        400, 'restricted_response_type', {
          error_description: 'response_type not allowed for this client',
        });

      yield next;
    },

    function * checkRedirectUri(next) {
      // Validate: redirect_uri param

      this.oidc.redirectUriCheckPerformed = true;
      this.assert(this.oidc.client.redirectUriAllowed(this.oidc.params.redirect_uri),
        new errors.RedirectUriMismatchError());


      yield next;
    },

    function * assignDefaults(next) {
      const params = this.oidc.params;
      const client = this.oidc.client;

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

      const params = this.oidc.params;

      // Assert response_type !none !id_token
      if (provider.configuration('features.claimsParameter') && params.claims !== undefined) {
        this.assert(params.response_type !== 'none', new errors.InvalidRequestError(
          'claims parameter should not be combined with response_type none'));

        let claims;

        try {
          claims = JSON.parse(params.claims);
        } catch (err) {
          this.throw(new errors.InvalidRequestError('could not parse the claims parameter JSON'));
        }

        this.assert(_.isPlainObject(claims),
          new errors.InvalidRequestError('claims parameter should be a JSON object'));

        this.assert(claims.userinfo !== undefined || claims.id_token !== undefined,
          new errors.InvalidRequestError(
            'claims parameter should have userinfo or id_token properties'));

        this.assert(claims.userinfo === undefined || _.isPlainObject(claims.userinfo),
          new errors.InvalidRequestError('claims.userinfo should be an object'));

        this.assert(claims.id_token === undefined || _.isPlainObject(claims.id_token),
          new errors.InvalidRequestError('claims.id_token should be an object'));

        this.assert(params.response_type !== 'id_token' || !claims.userinfo,
          new errors.InvalidRequestError(
            'claims.userinfo should not be used if access_token is not issued'));

        this.oidc.claims = claims;
      }

      if (params.max_age || this.oidc.client.requireAuthTime) {
        _.merge(this.oidc.claims, { id_token: { auth_time: { essential: true } } });
      }

      const acrValues = params.acr_values;

      if (acrValues) {
        _.merge(this.oidc.claims, { id_token: { acr: { values: acrValues.split(' ') } } });
      }

      yield next;
    },

    function * loadAccount(next) {
      const accountId = this.oidc.session.accountId();

      if (accountId) {
        const Account = provider.get('Account');
        this.oidc.account = yield Account.findById(accountId);
      }

      yield next;
    },

    function * interactions(next) {
      // Validate: login required
      const ctx = this.oidc;
      const clientName = _.get(ctx.client, 'name', 'Client');

      const loginInteractions = [

        // no account id was found in the session info
        () => {
          if (!ctx.session.accountId()) {
            return {
              error: 'login_required',
              error_description: 'End-User authentication is required',
              reason: 'no_session',
              reason_description: 'Please Sign-in to continue.',
            };
          }
          return false;
        },

        // login was requested by the client by prompt parameter
        () => {
          if (ctx.prompted('login')) {
            return {
              error: 'login_required',
              error_description: 'End-User authentication could not be obtained',
              reason: 'login_prompt',
              reason_description: `${clientName} asks you to Sign-in again.`,
            };
          }
          return false;
        },

        // session is too old for this authorization request
        () => {
          if (ctx.session.past(ctx.params.max_age)) {
            return {
              error: 'login_required',
              error_description: 'End-User re-authentication could not be obtained',
              reason: 'max_age',
              reason_description: `${clientName} asks you to Sign-in again.`,
            };
          }
          return false;
        },

        // session subject value differs from the one requested
        () => {
          if (_.has(ctx.claims, 'id_token.sub.value')) {
            const subject = Claims.sub(ctx.session.accountId(), ctx.client.sectorIdentifier);
            if (ctx.claims.id_token.sub.value !== subject) {
              return {
                error: 'login_required',
                error_description: 'requested subject could not be obtained',
                reason: 'claims_id_token_sub_value',
                reason_description:
                  `${clientName} asks you to Sign-in with a specific identity.`,
              };
            }
          }
          return false;
        },

        // none of multiple authentication context class references requested
        // are met
        () => {
          let requestedAcr;
          if (
            _.get(ctx.claims, 'id_token.acr.essential') &&
            (requestedAcr = _.get(ctx.claims, 'id_token.acr.values'))
          ) {
            if (requestedAcr.indexOf(ctx.session.acr()) === -1) {
              return {
                error: 'login_required',
                error_description: 'none of the requested ACRs could not be obtained',
                reason: 'essential_acrs',
                reason_description: `${clientName} asks you to Sign-in using a specific method.`,
              };
            }
          }
          return false;
        },

        // single requested authentication context class reference is not met
        () => {
          let requestedAcr;
          if (
            _.get(ctx.claims, 'id_token.acr.essential') &&
            (requestedAcr = _.get(ctx.claims, 'id_token.acr.value'))
          ) {
            if (requestedAcr !== ctx.session.acr()) {
              return {
                error: 'login_required',
                error_description: 'requested ACR could not be obtained',
                reason: 'essential_acr',
                reason_description: `${clientName} asks you to Sign-in using a specific method.`,
              };
            }
          }
          return false;
        },

        // any unfulfilled prompts other than none or login
        () => {
          const missed = _.find(ctx.prompts, (prompt) => {
            if (prompt !== 'none' && ctx.prompted(prompt)) {
              return true;
            }
            return false;
          });

          if (missed) {
            return {
              error: missed === 'consent' ? 'consent_required' : 'interaction_required',
              error_description: `prompt ${missed} was not resolved`,
              reason: `${missed}_prompt`,
            };
          }

          return false;
        },
      ];

      let interaction;

      _.forEach(loginInteractions, (fn) => {
        if ((interaction = fn())) {
          return false;
        }
        return true;
      });

      if (!interaction && ctx.params.id_token_hint !== undefined) {
        let decoded;
        const actualSub = Claims.sub(ctx.session.accountId(), ctx.client.sectorIdentifier);

        try {
          const IdToken = provider.get('IdToken');
          decoded = yield IdToken.validate(
            ctx.params.id_token_hint, ctx.client);
          decoded = decoded.payload;
        } catch (err) {
          this.throw(new errors.InvalidRequestError(
            `could not validate id_token_hint (${err.message})`));
        }

        if (decoded.sub !== actualSub) {
          interaction = {
            error: 'login_required',
            error_description: 'id_token_hint and authenticated subject do not match',
            reason: 'id_token_hint',
            reason_description: `${clientName} asks that you Sign-in with a specific identity.`,
          };
        }
      }

      if (interaction) {
        _.defaults(interaction, {
          error: 'interaction_required',
          error_description: 'interaction is required from the end-user',
        });

        // If login but prompt(none) throw;
        this.assert(!ctx.prompted('none'), 302, interaction.error, {
          error_description: interaction.error_description,
        });

        const destination = provider.configuration('interactionUrl')(this);
        const cookieOptions = provider.configuration('cookies.short');

        this.cookies.set('_grant', j({
          interaction,
          uuid: ctx.uuid,
          returnTo: ctx.urlFor('resume', { grant: ctx.uuid }),
          params: ctx.params,
        }), Object.assign({ path: url.parse(destination).pathname }, cookieOptions));

        this.cookies.set('_grant', j(ctx.params), Object.assign({
          path: ctx.pathFor('resume', { grant: ctx.uuid }),
        }, cookieOptions));

        return this.redirect(destination);
      }

      return yield next;
    },

    function * respond(next) {
      const out = yield next;

      if (this.oidc.params.state !== undefined) {
        out.state = this.oidc.params.state;
      }

      provider.emit('authorization.success', this);

      if (provider.configuration('features.sessionManagement')) {
        const statesCookieName = '_session_states';
        const salt = crypto.randomBytes(8).toString('hex');
        const state = String(this.oidc.session.authTime());

        const shasum = crypto.createHash('sha256')
          .update(this.oidc.params.client_id)
          .update(' ')
          .update(sessionOrigin(this.oidc.params.redirect_uri))
          .update(' ')
          .update(state)
          .update(' ')
          .update(salt);

        const sessionStr = shasum.digest('hex');
        const states = {};
        try {
          Object.assign(states, JSON.parse(this.cookies.get(statesCookieName, {
            signed: provider.configuration('cookies.long.signed'),
          })));
        } catch (err) {}

        states[this.oidc.params.client_id] = state;

        this.cookies.set(statesCookieName, j(states),
          Object.assign({}, provider.configuration('cookies.long'), { httpOnly: false }));

        out.session_state = `${sessionStr}.${salt}`;
      }

      if (this.oidc.params.response_mode === 'form_post') {
        formPost.call(this, this.oidc.params.redirect_uri, out);
      } else {
        const uri = redirectUri(this.oidc.params.redirect_uri, out, this.oidc.params.response_mode);
        this.redirect(uri);
      }
    },

    function * handleSuccess() {
      const responses = this.oidc.params.response_type.split(' ');
      const out = Object.assign.apply({}, yield responses.map(rt => handlers[rt].apply(this)));

      if (out.access_token && out.id_token) {
        out.id_token.set('at_hash', out.access_token);
      }

      if (out.code && out.id_token) {
        out.id_token.set('c_hash', out.code);
      }

      if (out.id_token) {
        out.id_token = yield out.id_token.sign(this.oidc.client);
      }

      return out;
    },
  ]);
};
