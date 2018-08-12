const legacy = require('./legacy');
const opaque = require('./opaque');
const jwt = require('./jwt');
const dynamic = require('./dynamic');

module.exports = {
  dynamic,
  jwt,
  legacy,
  opaque,
};
