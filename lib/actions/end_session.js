'use strict';

let compose = require('koa-compose');

let errors = require('../helpers/errors');
let JWT = require('../helpers/jwt');
let presence = require('../helpers/validate_presence');
let redirectUri = require('../helpers/redirect_uri');

let dupesMiddleware = require('../middlewares/check_dupes');
let paramsMiddleware = require('../middlewares/get_params');

const PARAM_LIST = [
  'id_token_hint',
  'post_logout_redirect_uri',
  'state',
];

let getParams = paramsMiddleware({
  whitelist: PARAM_LIST,
});

module.exports = function (provider) {

  let loadClient = function * loadClient(clientId) {
    // Validate: client_id param
    let client = provider.Client.find(clientId);

    this.assert(client,
      new errors.InvalidRequestError('unrecognized client_id'));

    return client;

  };

  return compose([

    getParams,

    dupesMiddleware,

    function * (next) {
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
      this.cookies.set('_session_states', null, {signed: true});
      this.cookies.set('_session', null, {signed: true});

      let afterLogout = this.oidc.params.post_logout_redirect_uri ?
        this.oidc.params.post_logout_redirect_uri : '/';

      let uri = redirectUri(afterLogout, {
        state: this.oidc.params.state
      });

      this.redirect(uri);

      yield next;
    },
  ]);
};
