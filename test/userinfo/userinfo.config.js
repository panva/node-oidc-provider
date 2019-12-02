const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.findAccount = (ctx, id) => {
  if (id === 'notfound') return undefined;
  return {
    accountId: id,
    claims() { return { sub: id, email: 'foo@example.com', email_verified: false }; },
  };
};

config.claims = {
  email: ['email', 'email_verified'],
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
