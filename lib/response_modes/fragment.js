import formatUri from '../helpers/redirect_uri.js';

export default (ctx, redirectUri, payload) => {
  const isXHR = ctx.get('x-requested-with') === 'XMLHttpRequest';
  const uri = formatUri(redirectUri, payload, 'fragment');

  if(isXHR) {
    ctx.status = 200;
    ctx.body = { code: 303, uri };
  }
  else {
    ctx.status = 303;
    ctx.redirect(uri);
  }
};
