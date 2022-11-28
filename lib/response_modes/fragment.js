const formatUri = require('../helpers/redirect_uri.js');

module.exports = (ctx, redirectUri, payload) => {
  const uri = formatUri(redirectUri, payload, 'fragment');
  ctx.status = 303;
  ctx.redirect(uri);
};
