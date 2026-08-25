export default function assertProviderContext(provider, ctx) {
  if (ctx?.oidc?.provider !== provider) {
    throw new TypeError('provider does not match ctx.oidc.provider');
  }
}
