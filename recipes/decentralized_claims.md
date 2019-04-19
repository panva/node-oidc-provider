# Aggregated and Distributed claims

Returning aggregated and distributed claims is as easy as having your account#claims method return
the two necessary members `_claim_sources` and `_claim_names` with the
[expected][aggregated-distributed-claims] properties. oidc-provider will include only the
sources for claims that are part of the request scope, omitting the ones that the RP did not request
and leaving out the entire `_claim_sources` and `_claim_sources` if they bear no requested claims.

Note: to make sure the RPs can expect these claims you should configure your discovery to return
the respective claim types via the `claim_types_supported` property.
```js
const oidc = new Provider('http://localhost:3000', {
  discovery: {
    claim_types_supported: ['normal', 'aggregated', 'distributed']
  }
});
```
