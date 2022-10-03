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

const RENDER_MODES = new Set(['form_post', 'web_message']);

module.exports = async function jwtResponseModes(ctx, redirectUri, payload) {
  const { params } = ctx.oidc;

  let mode;
  if (params.response_mode === 'jwt') {
    if (typeof params.response_type === 'string' && params.response_type.includes('token')) {
      mode = 'fragment';
    } else {
      mode = 'query';
    }
  } else {
    ([mode] = params.response_mode.split('.'));
  }

  const { IdToken } = this;
  const token = new IdToken({}, { ctx });
  token.extra = payload;

  const response = await token.issue({ use: 'authorization' });

  if (RENDER_MODES.has(mode)) {
    if ('error' in payload && payload.error !== 'server_error') {
      ctx.status = 400;
    }
  }

  return modes[mode](ctx, redirectUri, { response });
};
