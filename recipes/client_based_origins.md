# Client Metadata-based CORS Origin whitelist

- built for version: ^6.0.0
- no guarantees this is bug-free

OIDC routes that are ever needed to be called from a browser user-agent are CORS-enabled and by
default have all origins whitelisted. This works for developing and testing but at some point you
might want to restrict the call's origins.

These endpoints have CORS enabled from all origins all the time, no real reason to restrict it:

- jwks (`jwks_uri`)
- discovery (`/.well-known/openid-configuration`)

These endpoints have CORS enabled from all origins by default:

- `device_authorization_endpoint`
- `introspection_endpoint`
- `revocation_endpoint`
- `token_endpoint`
- `userinfo_endpoint`

As these always get their client resolved during the request (either through client authentication
or the token's client) you can use any mechanism available to you to have them fail the moment
client is identified. In this recipe we'll use a custom client metadata to register an array of
origins that will be allowed when  encountered, otherwise the requests will fail.

Since neither one of the specifications defines metadata for client's allowed CORS origins here's
how to implement a custom client metadata field and have it used during CORS requests (both actual
and preflights).

```js
const { URL } = require('url');

const { errors: { InvalidClientMetadata } } = Provider;

const corsProp = 'urn:custom:client:allowed-cors-origins';
const isOrigin = (value) => {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    const { origin } = new URL(value);
    // Origin: <scheme> "://" <hostname> [ ":" <port> ]
    return value === origin;
  } catch (err) {
    return false;
  }
}

new Provider(/* your issuer */, {
  extraClientMetadata: {
    properties: [corsProp],
    validator(key, value, metadata) {
      if (key === corsProp) {
        // set default (no CORS)
        if (value === undefined) {
          metadata[corsProp] = [];
          return;
        }
        // validate an array of Origin strings
        if (!Array.isArray(value) || !value.every(isOrigin)) {
          throw new InvalidClientMetadata(`${corsProp} must be an array of origins`);
        }
      }
    },
  },
  clientBasedCORS(ctx, origin, client) {
    // ctx.oidc.route can be used to exclude endpoints from this behaviour, in that case just return
    // true to always allow CORS on them, false to deny
    // you may also allow some known internal origins if you want to
    return client[corsProp].includes(origin);
  },
  ...rest // of your configuration
});
```
