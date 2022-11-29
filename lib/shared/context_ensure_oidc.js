export default function getContextEnsureOidc({ OIDCContext }) {
  return async function contextEnsureOidc(ctx, next) {
    Object.defineProperty(ctx, 'oidc', { value: new OIDCContext(ctx) });
    await next();
  };
}
