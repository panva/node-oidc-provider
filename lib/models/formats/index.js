const opaque = require('./opaque.js');
const jwt = require('./jwt.js');
const dynamic = require('./dynamic.js');

module.exports = (provider) => {
  const result = {
    opaque: opaque(provider), // no dependencies
  };

  result.jwt = jwt(provider, result); // depends on opaque
  result.dynamic = dynamic(provider, result); // depends on all

  return result;
};
