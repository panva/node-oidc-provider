import { InvalidTarget } from '../../helpers/errors.js';
import { applyDpopBinding } from '../../helpers/grant_common.js';

export const handler = async function clientCredentialsHandler(provider, helpers, ctx) {
  const {
    checkDpopRequired,
    checkMtlsCert,
    validateDpop,
    applyAuthorizationDetails,
    buildTokenResponse,
    resolveRequestedResources,
    validateClientScope,
  } = helpers;

  const { client } = ctx.oidc;
  const { ClientCredentials } = provider;

  const dPoP = await validateDpop(ctx);

  const resourceServers = await resolveRequestedResources(ctx);
  const scopes = [...validateClientScope(ctx)];

  const token = new ClientCredentials({
    client,
    scope: scopes.join(' ') || undefined,
  });

  const { 0: resourceServer, length } = resourceServers;
  if (resourceServer) {
    if (length !== 1) {
      throw new InvalidTarget('only a single resource indicator value is supported for this grant type');
    }
    token.resourceServer = resourceServer;
    token.scope = scopes.filter(Set.prototype.has.bind(new Set(resourceServer.scope.split(' ')))).join(' ') || undefined;
  }

  const cert = checkMtlsCert(ctx);
  if (cert) {
    token.setThumbprint('x5t', cert);
  }

  await applyDpopBinding(provider, ctx, dPoP, token);
  checkDpopRequired(ctx, dPoP);
  await applyAuthorizationDetails(ctx, token);

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save();

  ctx.body = buildTokenResponse({
    accessToken: value,
    authorizationDetails: token.rar,
    expiresIn: token.expiration,
    scope: token.scope || undefined,
    tokenType: token.tokenType,
  });
};

export const parameters = new Set(['scope']);

export const grantType = 'client_credentials';
