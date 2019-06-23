# using mutual-TLS features with caddy webserver

- built for version: ^6.0.0

Caddy, unlike Nginx or Apache, is escaping and url safing the cert values when passing them as
headers.

When oidc-provider uses [`ctx.get`](https://koajs.com/#request-get-field-) to fetch the
`x-ssl-client-cert` value you have to return the unmodified one. Here's how

```js
provider.use((ctx, next) => {
  if (ctx.secure) {
    const orig = ctx.get;

    ctx.get = function get(header) {
      const value = orig.call(ctx, header);

      if (header.toLowerCase() === 'x-ssl-client-cert') {
        return unescape(value.replace(/\+/g, ' '));
      }

      return value;
    };
  }

  return next();
}
