# Applying default client scope

- built for version: ^8.0.0
- no guarantees this is bug-free, no support will be provided for this, you've been warned, you're on
your own

```js
const oidcConfiguration = {
  extraParams: {
    scope(ctx, value, client) {
      ctx.oidc.params.scope ||= value ||= client.scope;
    }
  }
};
const provider = new Provider(ISSUER, oidcConfiguration); // finally, configure your provider
```
