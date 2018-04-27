const { struct } = require('../struct');
const { ttl: defaults } = require('../../lib/helpers/defaults');

module.exports = struct.dict(['string', 'integer & positive'], defaults);
