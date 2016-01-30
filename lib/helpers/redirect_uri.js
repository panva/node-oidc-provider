'use strict';

let url = require('url');
let querystring = require('querystring');

module.exports = function(redirectUri, payload, mode) {
  let parsed = url.parse(redirectUri, true);

  parsed.search = null;

  if (parsed.pathname === '/' && !redirectUri.endsWith('/')) {
    parsed.pathname = null;
  }

  switch (mode) {
  case 'fragment':
    parsed.hash = querystring.stringify(payload);
    break;
  default:
    Object.assign(parsed.query, payload);
    break;
  }

  return url.format(parsed);
};
