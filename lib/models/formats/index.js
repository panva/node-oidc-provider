const instance = require('../../helpers/weak_cache');

const opaque = require('./opaque');
const jwt = require('./jwt');
const jwtIetf = require('./jwt_ietf');
const paseto = require('./paseto');
const dynamic = require('./dynamic');

module.exports = (provider) => {
  const result = {
    opaque: opaque(provider), // no dependencies
  };

  result.jwt = jwt(provider, result); // depends on opaque
  result.paseto = paseto(provider, result); // depends on opaque

  if (instance(provider).configuration('features.ietfJWTAccessTokenProfile.enabled')) {
    result['jwt-ietf'] = jwtIetf(provider, result); // depends on opaque and jwt
  }

  result.dynamic = dynamic(provider, result); // depends on all

  return result;
};
