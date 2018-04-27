const { struct } = require('superstruct');
const { extraClientMetadata: defaults } = require('../../lib/helpers/defaults');

module.exports = struct({
  properties: ['string'],
  validator: 'function',
}, {
  properties: defaults.properties,
  validator() {
    return defaults.validator;
  },
});
