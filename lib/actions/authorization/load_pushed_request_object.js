const { PUSHED_REQUEST_URN } = require('../../consts');
const { InvalidRequestUri } = require('../../helpers/errors');

module.exports = async function loadPushedRequestObject(ctx) {
  const { params } = ctx.oidc;
  const [, id] = params.request_uri.split(PUSHED_REQUEST_URN);
  const requestObject = await ctx.oidc.provider.RequestObject.find(id);
  if (!requestObject) {
    throw new InvalidRequestUri('request_uri is invalid or expired');
  }
  ctx.oidc.entity('RequestObject', requestObject);
  return requestObject;
};
