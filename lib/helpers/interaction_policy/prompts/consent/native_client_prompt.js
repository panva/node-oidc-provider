const Check = require('../../check');

module.exports = () => new Check('native_client_prompt', 'native clients require End-User interaction', 'interaction_required', (ctx) => {
  const { oidc } = ctx;
  if (
    oidc.client.applicationType === 'native'
    && oidc.params.response_type !== 'none'
    && (!oidc.result || !('consent' in oidc.result))
  ) {
    return true;
  }

  return false;
});
