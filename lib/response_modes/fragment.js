import formatUri from '../helpers/redirect_uri.js';

export default (ctx, redirectUri, payload) => {
  const uri = formatUri(redirectUri, payload, 'fragment');
  ctx.status = 303;
  ctx.redirect(uri);
};
