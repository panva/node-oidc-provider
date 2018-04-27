const { struct } = require('../../struct');

module.exports = defaults => struct.interface({
  signed: 'boolean | undefined',
  secure: 'boolean | undefined',
  httpOnly: 'boolean',
  maxAge: 'integer & ms',
}, defaults);
