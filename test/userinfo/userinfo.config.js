const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.findById = (ctx, id) => {
  if (id === 'notfound') return undefined;
  return {
    accountId: id,
    claims() { return { sub: id }; },
  };
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token'],
    redirect_uris: ['https://client.example.com/cb'],
  }
};
