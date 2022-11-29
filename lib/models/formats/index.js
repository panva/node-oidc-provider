import opaque from './opaque.js';
import jwt from './jwt.js';
import dynamic from './dynamic.js';

export default (provider) => {
  const result = {
    opaque: opaque(provider), // no dependencies
  };

  result.jwt = jwt(provider, result); // depends on opaque
  result.dynamic = dynamic(provider, result); // depends on all

  return result;
};
