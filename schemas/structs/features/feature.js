const { struct } = require('../../struct');

module.exports = function feature(enabled, schema, defaults) {
  return struct(Object.assign({
    enabled: 'boolean',
  }, schema), Object.assign({
    enabled,
  }, defaults));
};
