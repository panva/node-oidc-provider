const formatUri = require('../helpers/redirect_uri');

module.exports = (ctx, redirectUri, payload) => {
  const uri = formatUri(redirectUri, payload, 'query');
  ctx.status = 303;
  ctx.redirect(uri);
};
