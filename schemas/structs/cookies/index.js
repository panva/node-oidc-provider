const { struct } = require('superstruct');
const names = require('./names');
const options = require('./options');
const {
  cookies:
  {
    keys,
    long,
    short,
  },
} = require('../../../lib/helpers/defaults');

module.exports = struct.interface({
  names,
  long: options(long),
  short: options(short),
  keys: ['string'],
}, {
  names: {},
  short: {},
  long: {},
  keys,
});
