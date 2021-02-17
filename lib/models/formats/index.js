const opaque = require('./opaque');
const jwt = require('./jwt');
const paseto = require('./paseto');
const dynamic = require('./dynamic');

module.exports = (provider) => {
  const result = {
    opaque: opaque(provider), // no dependencies
  };

  result.jwt = jwt(provider, result); // depends on opaque
  result.paseto = paseto(provider, result); // depends on opaque
  result.dynamic = dynamic(provider, result); // depends on all

  return result;
};
