# Accepting Dynamic OP Scope Values

- built for version: ^7.1.2 || ^8.0.0
- For dynamic scopes at the Resource Server you'd use the helpers in the `resourceIndicators` feature.

```js
// our dynamic scope is in the format "dynamic:{3 digits}"
const requestParamOIDCScopes = Object.getOwnPropertyDescriptor(provider.OIDCContext.prototype, 'requestParamOIDCScopes').get;
Object.defineProperty(provider.OIDCContext.prototype, 'requestParamOIDCScopes', {
  get() {
    const scopes = this.requestParamScopes;
    const recognizedScopes = requestParamOIDCScopes.call(this);
    for (const scope of scopes) {
      if (/^dynamic:\d{3}$/.exec(scope)) {
        recognizedScopes.add(scope);
      }
    }
    return recognizedScopes;
  },
});
```
