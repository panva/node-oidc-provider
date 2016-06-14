'use strict';

const compose = require('koa-compose');

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const presence = require('../helpers/validate_presence');
const redirectUri = require('../helpers/redirect_uri');

const dupesMiddleware = require('../middlewares/check_dupes');
const bodyMiddleware = require('../middlewares/selective_body');
const paramsMiddleware = require('../middlewares/get_params');

const PARAM_LIST = [
  'id_token_hint',
  'post_logout_redirect_uri',
  'state',
];

const getParams = paramsMiddleware({ whitelist: PARAM_LIST });
const body = bodyMiddleware('application/x-www-form-urlencoded');

module.exports = function endSessionAction(provider) {
  const loadClient = function * loadClient(clientId) {
    // Validate: client_id param
    const client = yield provider.Client.find(clientId);

    this.assert(client,
      new errors.InvalidClientError('unrecognized azp or aud claims'));

    return client;
  };

  return compose([

    function * parseBody(next) {
      if (this.method === 'POST') {
        yield body.call(this, next);
      } else {
        yield next;
      }
    },

    getParams,

    dupesMiddleware,

    function * validateIdTokenHintPresence(next) {
      presence.call(this, ['id_token_hint']);
      yield next;
    },

    function * endSession(next) {
      const params = this.oidc.params;
      let client;
      let clientId;

      try {
        const jot = JWT.decode(params.id_token_hint);
        clientId = jot.payload.azp || jot.payload.aud;
      } catch (err) {
        this.throw(new errors.InvalidRequestError(
          `could not decode id_token_hint (${err.message})`));
      }

      try {
        client = yield loadClient.call(this, clientId);
        yield provider.IdToken.validate(
          params.id_token_hint, client);
      } catch (err) {
        this.throw(new errors.InvalidRequestError(
          `could not validate id_token_hint (${err.message})`));
      }

      if (params.post_logout_redirect_uri) {
        this.assert(client.postLogoutRedirectUriAllowed(
          params.post_logout_redirect_uri),
          new errors.InvalidRequestError(
            'post_logout_redirect_uri not registered'));
      }

      if (!params.post_logout_redirect_uri && client.postLogoutRedirectUris.length === 1) {
        params.post_logout_redirect_uri = client.postLogoutRedirectUris[0];
      }

      yield this.oidc.session.destroy();
      this.cookies.set('_session_states', null);
      this.cookies.set('_session_states.sig', null);
      this.cookies.set('_session', null);
      this.cookies.set('_session.sig', null);

      const afterLogout = params.post_logout_redirect_uri ? params.post_logout_redirect_uri : '/';

      const uri = redirectUri(afterLogout, params.state !== undefined ? {
        state: params.state,
      } : undefined);

      this.redirect(uri);

      yield next;
    },
  ]);
};
