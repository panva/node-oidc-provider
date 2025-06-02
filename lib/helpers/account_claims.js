export default async function getCtxAccountClaims(ctx, use, scope, claims, rejected) {
  return {
    ...await ctx.oidc.account.claims(use, scope, claims, rejected),
    sub: ctx.oidc.account.accountId,
  };
}
