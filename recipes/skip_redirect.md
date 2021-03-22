# Render invalid_request errors

- built for version: ^7.1.0

```js
const { errors } = require('oidc-provider');
Object.defineProperty(errors.InvalidRequest.prototype, 'allow_redirect', { value: false });
```

This will make all `invalid_request` errors that would normally redirect back to the 
client's redirect_uri (when conditions allow) render instead.
