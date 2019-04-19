# OpenID Connect 1.0 Standard Claims

- built for version: ^6.0.0

The `claims` configuration parameter can be used to define which claims fall under what scope
as well as to expose additional claims that are available to RPs via the `claims` authorization
parameter.

```js
new Provider(/* your issuer */, {
  claims: {
    [scopeName]: ['claim name', 'claim name'],
    // or
    [scopeName]: {
      [claimName]: null,
    },
    // or (for standalone claims) - only requestable via claims parameter
    //   (when features.claimsParameter is true)
    [standaloneClaimName]: null
  }
});
```

To follow the [Core-defined scope-to-claim mapping][core-account-claims] use:

```js
new Provider(/* your issuer */, {
  claims: {
    address: ['address'],
    email: ['email', 'email_verified'],
    phone: ['phone_number', 'phone_number_verified'],
    profile: ['birthdate', 'family_name', 'gender', 'given_name', 'locale', 'middle_name', 'name',
      'nickname', 'picture', 'preferred_username', 'profile', 'updated_at', 'website', 'zoneinfo'],
  },
});
```

[core-account-claims]: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
