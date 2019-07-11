# Aggregated and Distributed claims

- built for version: ^6.0.0

Returning aggregated and distributed claims is as easy as having your `findAccount`'s `claims()`
method return the two necessary members `_claim_sources` and `_claim_names` with the
[expected](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims)
properties. oidc-provider will include only the sources for claims that are part of the request
scope, omitting the ones that the RP did not request and leaving out the entire `_claim_sources` and
`_claim_sources` if they bear no requested claims.

Note: to make sure the RPs can expect these claims you should configure your discovery to return
the respective claim types via the `claim_types_supported` property.

```js
const oidc = new Provider('http://localhost:3000', {
  async findAccount(ctx, sub, token) {
    return {
      accountId: sub,
      async claims(use, scope, claims, rejected) {
        return {
          sub,
          _claim_names: {
            address: 'src1',
            phone_number: 'src1',
            email: 'src2'
          },
          _claim_sources: {
            src1: { JWT: '...' },
            src2: { endpoint: 'https://rs.example.com/example', access_token: 'ksj3n283dke' }
          }
        };
      },
    }
  },
  discovery: {
    claim_types_supported: ['normal', 'aggregated', 'distributed']
  }
});
```
