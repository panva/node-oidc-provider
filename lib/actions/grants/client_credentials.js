import { InvalidTarget } from '../../helpers/errors.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import {
  applyDpopBinding,
  checkMtlsCert,
  checkDpopRequired,
} from '../../helpers/grant_common.js';

export const handler = async function clientCredentialsHandler(provider, helpers, ctx) {
  const {
    applyAuthorizationDetails,
    buildTokenResponse,
    resolveRequestedResources,
    validateClientScope,
  } = helpers;

  const { client } = ctx.oidc;
  const { ClientCredentials } = provider;

  const dPoP = await dpopValidate(ctx);

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

  const cert = checkMtlsCert(provider, ctx);
  if (cert) {
    token.setThumbprint('x5t', cert);
  }

  await applyDpopBinding(provider, ctx, dPoP, token);
  checkDpopRequired(provider, ctx, dPoP);
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
