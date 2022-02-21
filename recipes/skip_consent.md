# Skipping consent screen

- built for version: ^7.0.0
- no guarantees this is bug-free, no support will be provided for this, you've been warned, you're on
your own
- it is not recommended to have consent-free flows for the obvious issues this poses for native
applications

Sometimes your use-case doesn't need a consent screen.
This use-case might occur if your provider has only *first-party* clients configured.
To achieve that you want to add the requested claims/scopes/resource scopes to the grant:

```js
const oidcConfiguration = {
  loadExistingGrant(ctx) {
    const grantId = (ctx.oidc.result
      && ctx.oidc.result.consent
      && ctx.oidc.result.consent.grantId) || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);

    if (grantId) {
      // keep grant expiry aligned with session expiry
      // to prevent consent prompt being requested when grant expires
      const grant = await ctx.oidc.provider.Grant.find(grantId);

      // this aligns the Grant ttl with that of the current session
      // if the same Grant is used for multiple sessions, or is set
      // to never expire, you probably do not want this in your code
      if (ctx.oidc.account && grant.exp < ctx.oidc.session.exp) {
        grant.exp = ctx.oidc.session.exp;

        await grant.save();
      }

      return grant;
    } else if (isFirstParty(ctx.oidc.client)) {
      const grant = new ctx.oidc.provider.Grant({
        clientId: ctx.oidc.client.clientId,
        accountId: ctx.oidc.session.accountId,
      });

      grant.addOIDCScope('openid email profile');
      grant.addOIDCClaims(['first_name']);
      grant.addResourceScope('urn:example:resource-indicator', 'api:read api:write');
      await grant.save();
      return grant;
    }
  }
};
const provider = new Provider(ISSUER, oidcConfiguration); // finally, configure your provider
```

This will get you as far as not asking for any consent unless the application is a native
application (e.g. iOS, Android, CLI, Device Flow). It is recommended to still show a consent
screen to those with the application details to those since they are public clients and their
redirect_uri ownership can rarely be validated.
