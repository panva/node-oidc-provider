# Allowing HTTP and/or localhost for implicit response type web clients

- built for version: ^6.15.0

> ⚠️ This violates the OIDC Core 1.0 specification. **Its only practical use-case is for development purposes and as such is not recommended
> for any production deployment.**

```js
const { Provider } = require('oidc-provider');

const provider = new Provider('http://localhost:3000', {
  clients: [
    {
      client_id: 'development-implicit',
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      response_types: ['id_token'],
      grant_types: ['implicit'],
      redirect_uris: ['http://localhost:3001'], // this fails two regular validations http: and localhost
    },
  ],
});

const { invalidate: orig } = provider.Client.Schema.prototype;

provider.Client.Schema.prototype.invalidate = function invalidate(message, code) {
  if (code === 'implicit-force-https' || code === 'implicit-forbid-localhost') {
    return;
  }

  orig.call(this, message);
};
```

In addition to this you may also utilize
[extra client metadata](https://github.com/panva/node-oidc-provider/blob/master/docs/README.md#extraclientmetadata)
and only skip these checks for clients in something like a development mode or similar. Again, no
production client should be allowed to skip these validations.
