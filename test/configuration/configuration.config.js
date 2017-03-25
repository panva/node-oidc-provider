const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { encryption: true };

module.exports = {
  config
};
