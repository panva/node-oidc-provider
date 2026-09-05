import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import { account as validateAccount } from '../helpers/configuration_result.js';
import { InvalidToken } from '../helpers/errors.js';
import dpopValidate, { checkDpopReplay } from '../helpers/validate_dpop.js';
import instance from '../helpers/weak_cache.js';

export function getValidateAccessToken({ afterFind } = {}) {
  return async function validateAccessToken(ctx, next) {
    const value = ctx.oidc.getAccessToken({ acceptDPoP: true });
    const dPoP = await dpopValidate(ctx.oidc.provider, ctx, value);
    const accessToken = await ctx.oidc.provider.AccessToken.find(value);

    ctx.assert(accessToken, new InvalidToken('access token not found'));
    ctx.oidc.entity('AccessToken', accessToken);

    await afterFind?.(ctx, accessToken);

    if (accessToken['x5t#S256']) {
      const { getCertificate } = instance(ctx.oidc.provider).features.mTLS;
      const cert = getCertificate(ctx);
      if (!cert || accessToken['x5t#S256'] !== certificateThumbprint(cert)) {
        throw new InvalidToken('failed x5t#S256 verification');
      }
    }

    await checkDpopReplay(ctx.oidc.provider, ctx, dPoP, accessToken.clientId, InvalidToken);

    if (dPoP && !accessToken.jkt) {
      throw new InvalidToken(
        'access token is not sender-constrained but proof of possession was provided',
      );
    }

    if (accessToken.jkt && (!dPoP || accessToken.jkt !== dPoP.thumbprint)) {
      throw new InvalidToken('failed jkt verification');
    }

    await next();
  };
}

export async function loadAccessTokenClient(ctx, next) {
  const client = await ctx.oidc.provider.Client.find(ctx.oidc.accessToken.clientId);
  ctx.assert(client, new InvalidToken('associated client not found'));
  ctx.oidc.entity('Client', client);
  await next();
}

export async function loadAccessTokenAccount(ctx, next) {
  const account = validateAccount(
    await instance(ctx.oidc.provider).configuration.findAccount(
      ctx,
      ctx.oidc.accessToken.accountId,
      ctx.oidc.accessToken,
    ),
  );
  ctx.assert(account, new InvalidToken('associated account not found'));
  ctx.oidc.entity('Account', account);
  await next();
}

export async function loadAccessTokenGrant(ctx, next) {
  const grant = await ctx.oidc.provider.Grant.find(ctx.oidc.accessToken.grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidToken('grant not found');
  }

  if (grant.isExpired) {
    throw new InvalidToken('grant is expired');
  }

  if (grant.clientId !== ctx.oidc.accessToken.clientId) {
    throw new InvalidToken('clientId mismatch');
  }

  if (grant.accountId !== ctx.oidc.accessToken.accountId) {
    throw new InvalidToken('accountId mismatch');
  }

  ctx.oidc.entity('Grant', grant);
  await next();
}
