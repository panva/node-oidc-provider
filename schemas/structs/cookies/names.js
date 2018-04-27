const { struct } = require('superstruct');
const { cookies: { names } } = require('../../../lib/helpers/defaults');

module.exports = struct({
  session: 'string',
  interaction: 'string',
  resume: 'string',
  state: 'string',
}, { ...names });
