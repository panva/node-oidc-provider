const { clone } = require('lodash');

const config = clone(require('../default.config'));
const { interactionCheck } = require('../../lib/helpers/defaults');

config.extraParams = ['custom'];
config.features = { sessionManagement: true };

config.prompts = ['consent', 'login', 'none', 'custom'];
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
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
