import instance from './weak_cache.js';
import { InvalidGrant } from './errors.js';
import revoke from './revoke.js';
import assertProviderContext from './assert_provider_context.js';

export async function findGrantSource(provider, ctx, Model, value, label) {
  assertProviderContext(provider, ctx);

  const source = await Model.find(value, { ignoreExpiration: true });

  if (!source) {
    throw new InvalidGrant(`${label} not found`);
  }

  if (source.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  return source;
}

export async function consumeGrantSource(provider, ctx, source, label) {
  assertProviderContext(provider, ctx);

  if (source.consumed) {
    await revoke(ctx, source.grantId);
    throw new InvalidGrant(`${label} already consumed`);
  }

  await source.consume();
}

export async function validateGrant(provider, ctx, grantId) {
  assertProviderContext(provider, ctx);

  const grant = await provider.Grant.find(grantId, {
    ignoreExpiration: true,
  });

  if (!grant) {
    throw new InvalidGrant('grant not found');
  }

  if (grant.isExpired) {
    throw new InvalidGrant('grant is expired');
  }

  if (grant.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  return grant;
}

export async function findAccount(provider, ctx, accountId, source) {
  assertProviderContext(provider, ctx);

  return instance(provider).configuration.findAccount(ctx, accountId, source);
}
