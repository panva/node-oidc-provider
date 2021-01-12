/* eslint-disable camelcase, max-len */

const Prompt = require('../../prompt');

const no_session = require('./no_session');
const max_age = require('./max_age');
const id_token_hint = require('./id_token_hint');
const claims_id_token_sub_value = require('./claims_id_token_sub_value');
const essential_acrs = require('./essential_acrs');
const essential_acr = require('./essential_acr');

module.exports = () => new Prompt(
  { name: 'login', requestable: true },

  (ctx) => {
    const { oidc } = ctx;

    return {
      ...(oidc.params.max_age === undefined ? undefined : { max_age: oidc.params.max_age }),
      ...(oidc.params.login_hint === undefined ? undefined : { login_hint: oidc.params.login_hint }),
      ...(oidc.params.id_token_hint === undefined ? undefined : { id_token_hint: oidc.params.id_token_hint }),
    };
  },

  no_session(),
  max_age(),
  id_token_hint(),
  claims_id_token_sub_value(),
  essential_acrs(),
  essential_acr(),
);
