const { struct, notEmpty } = require('../struct');
const defaults = require('../../lib/helpers/defaults');

module.exports = struct.intersection([
  struct.dict(['string', struct.union(['null', notEmpty(['string'])])], defaults.claims),
  struct.interface({
    openid(value) {
      if (!Array.isArray(value)) return 'openid not array';
      if (!value.includes('sub')) return 'sub missing in openid';
      return true;
    },
    acr(value) {
      if (value !== null) return 'acr not null';
      return true;
    },
    iss(value) {
      if (value !== null) return 'iss not null';
      return true;
    },
    auth_time(value) {
      if (value !== null) return 'auth_time not null';
      return true;
    },
  }),
]);
