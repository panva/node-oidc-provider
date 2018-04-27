const { superstruct } = require('superstruct');
const url = require('url');
const assert = require('assert');
const validUrl = require('../lib/helpers/valid_url');

const struct = superstruct({
  types: {
    issuerIdentifier(v) {
      try {
        assert(validUrl.isWebUri(v), 'must be a valid web uri');
        const components = url.parse(v);
        assert(components.host, 'Issuer Identifier must have a host component');
        assert(!components.search, 'must not have a query component');
        assert(!components.hash, 'must not have a fragment component');
      } catch (err) {
        return err.message;
      }
      return true;
    },
    email(v) {
      return /.+@.+\..+/.exec(v);
    },
    ms(v) {
      return v % 1000 === 0;
    },
    integer(v) {
      return Number.isInteger(v);
    },
    positive(v) {
      return v > 0;
    },
    zero(v) {
      return v === 0;
    },
    infinity(v) {
      return v === Infinity;
    },
    responseType(v) {
      const types = v.split(' ');

      if (!types.every(f => ['code', 'id_token', 'token'].includes(f)) && types[0] !== 'none') {
        return 'invalid response type';
      }

      if (!types.reduce((memo, item) => memo && item >= memo && item)) {
        return 'response types must be sorted';
      }

      return true;
    },
    route(v) {
      return v.startsWith('/') && !v.includes('#');
    },
    hasMembers(v) {
      return v.length > 0 ? true : 'must not be empty';
    },
  },
});

module.exports.struct = struct;

module.exports.notEmpty = function notEmpty(what) {
  return struct.intersection([what, 'hasMembers']);
};
