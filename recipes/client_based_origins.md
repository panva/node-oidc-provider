# Client Metadata-based CORS Origin allow list

- built for version: ^8.0.0
- no guarantees this is bug-free

Since the specifications do not define metadata for client's allowed CORS origins here's
how to implement a custom client metadata field and have it used during CORS requests
in the `clientBasedCORS` helper function.

```js
import { URL } from 'node:url';

import Provider, { errors } from 'oidc-provider'

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
    validator(ctx, key, value, metadata) {
      if (key === corsProp) {
        // set default (no CORS)
        if (value === undefined) {
          metadata[corsProp] = [];
          return;
        }
        // validate an array of Origin strings
        if (!Array.isArray(value) || !value.every(isOrigin)) {
          throw new errors.InvalidClientMetadata(`${corsProp} must be an array of origins`);
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
