import instance from './weak_cache.js';
import { setRefreshTokenBindings } from './set_rt_bindings.js';
import assertProviderContext from './assert_provider_context.js';

export async function shouldIssueRefreshToken(provider, ctx, source) {
  assertProviderContext(provider, ctx);

  return !!await instance(provider).configuration.issueRefreshToken(
    ctx,
    ctx.oidc.client,
    source,
  );
}

export function applyRefreshTokenBindings(provider, ctx, accessToken, refreshToken) {
  assertProviderContext(provider, ctx);
  return setRefreshTokenBindings(ctx, accessToken, refreshToken);
}
