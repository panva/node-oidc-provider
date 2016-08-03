'use strict';

const compose = require('koa-compose');

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const presence = require('../helpers/validate_presence');
const redirectUri = require('../helpers/redirect_uri');

const rejectDupes = require('../middlewares/check_dupes');
const bodyParser = require('../middlewares/conditional_body');
const paramsMiddleware = require('../middlewares/get_params');

const PARAM_LIST = [
  'id_token_hint',
  'post_logout_redirect_uri',
  'state',
];

const getParams = paramsMiddleware(PARAM_LIST);
const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function endSessionAction(provider) {
  const loadClient = function * loadClient(clientId) {
    // Validate: client_id param
    const client = yield provider.get('Client').find(clientId);

    this.assert(client,
      new errors.InvalidClientError('unrecognized azp or aud claims'));

    return client;
  };

  return compose([

    parseBody,

    getParams,

    rejectDupes,

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
        yield provider.get('IdToken').validate(params.id_token_hint, client);
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


      if (provider.configuration('features.backchannelLogout')) {
        try {
          const Client = provider.get('Client');
          const cookieValue = this.cookies.get('_session_states', {
            signed: provider.configuration('cookies.long.signed'),
          });

          const clientIds = Object.keys(JSON.parse(cookieValue));
          const logouts = clientIds.map(visitedClientId => Client.find(visitedClientId)
            .then(visitedClient => {
              if (visitedClient && visitedClient.backchannelLogoutUri) {
                return visitedClient.backchannelLogout();
              }
              return undefined;
            })
          );

          yield logouts;
        } catch (err) {}
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
