import instance from '../../helpers/weak_cache.js';
import {
  InvalidTarget, InvalidScope, InvalidRequest,
} from '../../helpers/errors.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import checkResource from '../../shared/check_resource.js';
import {
  checkMtlsCert,
  applyDpopBinding,
  checkDpopRequired,
} from '../../helpers/grant_common.js';

export const handler = async function clientCredentialsHandler(ctx) {
  const { client } = ctx.oidc;
  const { ClientCredentials } = ctx.oidc.provider;
  const {
    features: {
      mTLS: { getCertificate },
      dPoP: { allowReplay },
    },
    scopes: statics,
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  if (ctx.oidc.params.authorization_details) {
    throw new InvalidRequest('authorization_details is unsupported for this grant_type');
  }

  await checkResource(ctx, () => {});

  const scopes = [...new Set(ctx.oidc.params.scope?.split(' '))];

  if (client.scope) {
    const allowList = new Set(client.scope.split(' '));

    for (const scope of scopes.filter(Set.prototype.has.bind(statics))) {
      if (!allowList.has(scope)) {
        throw new InvalidScope('requested scope is not allowed', scope);
      }
    }
  }

  const token = new ClientCredentials({
    client,
    scope: scopes.join(' ') || undefined,
  });

  const { 0: resourceServer, length } = Object.values(ctx.oidc.resourceServers);
  if (resourceServer) {
    if (length !== 1) {
      throw new InvalidTarget('only a single resource indicator value is supported for this grant type');
    }
    token.resourceServer = resourceServer;
    token.scope = scopes.filter(Set.prototype.has.bind(new Set(resourceServer.scope.split(' ')))).join(' ') || undefined;
  }

  const cert = checkMtlsCert(ctx, getCertificate);
  if (cert) {
    token.setThumbprint('x5t', cert);
  }

  await applyDpopBinding(ctx, dPoP, token, allowReplay);
  checkDpopRequired(ctx, dPoP);

  ctx.oidc.entity('ClientCredentials', token);
  const value = await token.save();

  ctx.body = {
    access_token: value,
    expires_in: token.expiration,
    token_type: token.tokenType,
    scope: token.scope || undefined,
  };
};

export const parameters = new Set(['scope']);

export const grantType = 'client_credentials';
