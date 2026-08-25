import assertProviderContext from './assert_provider_context.js';
import { boolean } from './configuration_result.js';
import { setRefreshTokenBindings } from './set_rt_bindings.js';
import instance from './weak_cache.js';

export async function shouldIssueRefreshToken(provider, ctx, source) {
  assertProviderContext(provider, ctx);

  return boolean(
    await instance(provider).configuration.issueRefreshToken(
      ctx,
      ctx.oidc.client,
      source,
    ),
    'issueRefreshToken',
  );
}

export function applyRefreshTokenBindings(provider, ctx, accessToken, refreshToken) {
  assertProviderContext(provider, ctx);
  return setRefreshTokenBindings(ctx, accessToken, refreshToken);
}
