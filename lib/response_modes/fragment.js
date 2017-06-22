const formatUri = require('../helpers/redirect_uri');

module.exports = (ctx, redirectUri, payload) => {
  const uri = formatUri(redirectUri, payload, 'fragment');
  ctx.redirect(uri);
};
