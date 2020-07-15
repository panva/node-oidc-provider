if (!('DEBUG' in process.env)) {
  process.env.DEBUG = 'runner';
}

const debug = require('debug')('runner');

module.exports = debug;
