const { clone } = require('lodash');

const config = clone(require('../../default.config'));
const { interactionCheck } = require('../../../lib/helpers/defaults');

config.extraParams = ['custom'];
config.features = { requestUri: false };
config.interactionCheck = async (ctx) => {
  let interaction = await interactionCheck(ctx);

  if (!interaction) {
    if (ctx.oidc.params.custom) {
      interaction = {
        error: 'error_foo',
        error_description: 'error_description_foo',
        reason: 'reason_foo',
        reason_description: 'reason_description_foo.',
      };
    }
  }

  return interaction;
};

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    application_type: 'native',
    client_id: 'client-native',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['com.example.app:/cb'],
  }],
};
