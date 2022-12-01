import * as url from 'node:url';
import * as querystring from 'node:querystring';

export default function redirectUri(uri, payload, mode) {
  const parsed = url.parse(uri, true);

  parsed.search = null;

  // handles a case where url module adds unintended / to the pathname
  // i.e. http://www.example.com => http://www.example.com/
  if (parsed.pathname === '/' && !uri.endsWith('/')) parsed.pathname = null;

  switch (mode) {
    case 'fragment':
      parsed.hash = querystring.stringify(payload);
      break;
    default:
      Object.assign(parsed.query, payload);
      break;
  }

  return url.format(parsed);
}
