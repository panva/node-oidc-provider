/* eslint-disable no-param-reassign */

export async function setRefreshTokenBindings(ctx, at, rt) {
  switch (ctx.oidc.client.clientAuthMethod) {
    case 'none':
      if (at.jkt) {
        rt.jkt = at.jkt;
      }

      if (at['x5t#S256']) {
        rt['x5t#S256'] = at['x5t#S256'];
      }
      break;
    case 'attest_jwt_client_auth': {
      await rt.setAttestBinding(ctx);
      break;
    }
    default:
      break;
  }
}
