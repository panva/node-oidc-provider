'use strict';

const compose = require('koa-compose');

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');
const presence = require('../helpers/validate_presence');
const redirectUri = require('../helpers/redirect_uri');

const dupesMiddleware = require('../middlewares/check_dupes');
const paramsMiddleware = require('../middlewares/get_params');

const PARAM_LIST = [
  'id_token_hint',
  'post_logout_redirect_uri',
  'state',
];

const getParams = paramsMiddleware({ whitelist: PARAM_LIST });

module.exports = function endSessionAction(provider) {
  const loadClient = function * loadClient(clientId) {
    // Validate: client_id param
    const client = provider.Client.find(clientId);

    this.assert(client,
      new errors.InvalidRequestError('unrecognized client_id'));

    return client;
  };

  return compose([

    getParams,

    dupesMiddleware,

    function * validateIdTokenHintPresence(next) {
      presence.call(this, ['id_token_hint']);
      yield next;
    },

    function * endSession(next) {
      let client;

      try {
        client = yield loadClient.call(this,
          JWT.decode(this.oidc.params.id_token_hint).payload.aud);

        yield provider.IdToken.validate(
          this.oidc.params.id_token_hint, client);
      } catch (err) {
        this.throw(new errors.InvalidRequestError(
          'could not validate id_token_hint'));
      }

      if (this.oidc.params.post_logout_redirect_uri) {
        this.assert(client.postLogoutRedirectUriAllowed(
          this.oidc.params.post_logout_redirect_uri),
          new errors.InvalidRequestError(
            'post_logout_redirect_uri not registered'));
      }

      yield this.oidc.session.destroy();
      this.cookies.set('_session_states', null, { signed: true });
      this.cookies.set('_session', null, { signed: true });

      const afterLogout = this.oidc.params.post_logout_redirect_uri ?
        this.oidc.params.post_logout_redirect_uri : '/';

      const uri = redirectUri(afterLogout, {
        state: this.oidc.params.state,
      });

      this.redirect(uri);

      yield next;
    },
  ]);
};
