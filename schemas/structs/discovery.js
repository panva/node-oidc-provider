const { struct } = require('superstruct');
const defaults = require('../../lib/helpers/defaults');

module.exports = struct.dict(['string', 'any | undefined'], defaults.discovery);
