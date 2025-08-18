import instance from '../../helpers/weak_cache.js';
import {
  InvalidGrant, InvalidTarget, InvalidScope, InvalidRequest,
} from '../../helpers/errors.js';
import dpopValidate, { CHALLENGE_OK_WINDOW } from '../../helpers/validate_dpop.js';
import checkResource from '../../shared/check_resource.js';
import epochTime from '../../helpers/epoch_time.js';

export const handler = async function clientCredentialsHandler(ctx) {
  const { client } = ctx.oidc;
  const { ClientCredentials, ReplayDetection } = ctx.oidc.provider;
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

  if (client.tlsClientCertificateBoundAccessTokens) {
    const cert = getCertificate(ctx);

    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
    token.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    if (!allowReplay) {
      const unique = await ReplayDetection.unique(
        client.clientId,
        dPoP.jti,
        epochTime() + CHALLENGE_OK_WINDOW,
      );

      ctx.assert(unique, new InvalidGrant('DPoP proof JWT Replay detected'));
    }

    token.setThumbprint('jkt', dPoP.thumbprint);
  } else if (ctx.oidc.client.dpopBoundAccessTokens) {
    throw new InvalidGrant('DPoP proof JWT not provided');
  }

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
