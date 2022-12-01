import { PUSHED_REQUEST_URN } from '../../consts/index.js';
import { InvalidRequestUri } from '../../helpers/errors.js';

export default async function loadPushedAuthorizationRequest(ctx) {
  const { params } = ctx.oidc;
  const [, id] = params.request_uri.split(PUSHED_REQUEST_URN);
  const requestObject = await ctx.oidc.provider.PushedAuthorizationRequest.find(id, {
    ignoreExpiration: true,
  });
  if (!requestObject || requestObject.isExpired) {
    throw new InvalidRequestUri('request_uri is invalid or expired');
  }
  ctx.oidc.entity('PushedAuthorizationRequest', requestObject);

  await requestObject.destroy();

  return requestObject;
}
