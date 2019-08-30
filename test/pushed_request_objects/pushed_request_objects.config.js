const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.features = {
  pushedRequestObjects: { enabled: true },
};

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    request_object_signing_alg: 'HS256',
    redirect_uris: ['https://rp.example.com/cb'],
  }],
};
