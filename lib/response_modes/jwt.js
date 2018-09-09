/* eslint-disable camelcase */
const query = require('./query');
const fragment = require('./fragment');
const form_post = require('./form_post');
const web_message = require('./web_message');

const modes = {
  query,
  fragment,
  form_post,
  web_message,
};

module.exports = async function jwtResponseModes(ctx, redirectUri, payload) {
  const { params, client, entities: { AccessToken } } = ctx.oidc;

  let mode;
  if (params.response_mode === 'jwt') {
    if (String(params.response_type).includes('token')) {
      mode = 'fragment';
    } else {
      mode = 'query';
    }
  } else {
    ([mode] = params.response_mode.split('.'));
  }

  const { IdToken } = this;
  const token = new IdToken({}, client);
  token.extra = payload;

  if (payload.access_token) {
    token.set('scope', AccessToken.scope);
  }

  const response = await token.sign({ use: 'authorization' });

  return modes[mode](ctx, redirectUri, { response });
};
