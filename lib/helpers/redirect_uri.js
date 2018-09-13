const url = require('url');
const querystring = require('querystring');

module.exports = function redirectUri(uri, payload, mode) {
  const parsed = url.parse(uri, true);

  parsed.search = null;

  // handles a case where url module adds unintended / to the pathname
  // i.e. http://www.example.com => http://www.example.com/
  if (parsed.pathname === '/' && !uri.endsWith('/')) parsed.pathname = null;

  switch (mode) {
    case 'fragment':
      // TODO: temporary hack for backwards compatibility with existing AngularJS apps
      if (parsed.hash && parsed.hash.includes('login/success')) {
        parsed.hash = 'login/success?' + querystring.stringify(payload);
      } else {
        parsed.hash = querystring.stringify(payload);
      }
      break;
    default:
      Object.assign(parsed.query, payload);
      break;
  }

  return url.format(parsed);
};
