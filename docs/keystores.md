# Certificates, Keystores

**Notice: Follow the best practices for distributing private keying material and secrets!**

oidc-provider uses the [@panva/jose][jose-library] for everything JW(S|E|K) related.
oidc-provider expects to either receive a jose.JWKS.KeyStore object or a JWKS formatted javascript
object with the private keys during `#initialize()` call.

**Table of Contents**

- [Certificates Keystore (jwks_uri)](#certificates-keystore-jwks_uri)
- [Generating new keys](#generating-new-keys)
- [Generating all keys for all features](#generating-all-keys-for-all-features)
- [Signing Key Rotation](#signing-key-rotation)

## Certificates Keystore (jwks_uri)
To configure your Provider instance with your own signing and encryption keys you will need at the
very least a private RSA key in JSON Web Key (JWK) format. Since every provider MUST support RS256
signed ID Tokens a 'quick-start development only' keystore is used during `#initialize()` unless you
provide your own keystore. You can provide a private JWKS formatted javascript object or a
jose.JWKS.KeyStore object, either way works, with the same result.

```js
provider.initialize({
  keystore: {
    keys: [
      { kty, alg, e, n, d, p, q, dp, dq, qi, kid, use } // RSA JWK
    ]
  }
}).then(() => { /* your app is ready */ });

// or
provider.initialize({ keystore }).then(() => { /* your app is ready */ });
```



## Generating new keys
Refer to this snippet to generate a new random key using @panva/jose and get the JWK representation
of it. In this snippet a the required RS256 sig key is generated and a full JWKS is printed to the
console.

```js
const { JWKS: { KeyStore } } = require('@panva/jose');
const keystore = new KeyStore();
keystore.generateSync('RSA', 2048, {
  alg: 'RS256',
  use: 'sig',
});
console.log('this is the full private JWKS:\n', keystore.toJWKS(true));
```

## Generating all keys for all features
This script generates a sig/enc pair of private keys for all supported algorithms you can have if
you enable encryption features on your provider instance.

```js
const { JWKS: { KeyStore } } = require('@panva/jose');
const keystore = new KeyStore();
Promise.all([
  keystore.generate('RSA', 2048, {
    use: 'sig',
  }),
  keystore.generate('RSA', 2048, {
    use: 'enc',
  }),
  keystore.generate('EC', 'P-256', {
    use: 'sig',
  }),
  keystore.generate('EC', 'P-256', {
    use: 'enc',
  })
]).then(function () {
  console.log('my JWKS:\n', keystore.toJWKS(true));
});
```

## Signing Key Rotation
Following action order is recommended when rotating signing certificates keys on a
distributed deployment with rolling reloads in place.

1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become
  available for verification should they be encountered but not yet used for signing
2. reload all your processes
3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be
  used for signing
4. reload all your processes

[jose-library]: https://github.com/panva/jose
[jose-jwk]: https://tools.ietf.org/html/rfc7517
