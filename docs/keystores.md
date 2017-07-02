# Certificates, Keystores

**Notice: Follow the best practices for distributing private keying material and secrets!**

oidc-provider uses the brilliant [node-jose][node-jose-library] for everything JW(S|E|K) related.
oidc-provider expects to either receive a a jose.JWK.KeyStore object or a JWKS formatted javascript
object with the private keys during `#initialize()` call.

**Table of Contents**

<!-- TOC START min:2 max:2 link:true update:true -->
  - [Certificates Keystore (jwks_uri)](#certificates-keystore-jwks_uri)
  - [Generating new keys](#generating-new-keys)
  - [Generating all keys for all features](#generating-all-keys-for-all-features)
  - [Transforming existing keys from other formats](#transforming-existing-keys-from-other-formats)
  - [Signing Key Rotation](#signing-key-rotation)

<!-- TOC END -->

## Certificates Keystore (jwks_uri)
To configure your Provider instance with your own signing and encryption keys you will need at the
very least a private RSA key in JSON Web Key (JWK) format. Since every provider MUST support RS256
signed ID Tokens a 'quick-start development only' keystore is used during `#initialize()` unless you
provide your own keystore. You can provide a private JWKS formatted javascript object or a
jose.JWK.KeyStore object, either way works, with the same result.

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
Refer to this snippet to generate a new random key using node-jose and get the JWK representation
of it. In this snippet a the required RS256 sig key is generated and a full JWKS is printed to the
console.

```js
const { createKeyStore } = require('oidc-provider');
const keystore = createKeyStore();
keystore.generate('RSA', 2048, {
  alg: 'RS256',
  use: 'sig',
}).then(function () {
  console.log('this is the full private JWKS:\n', keystore.toJSON(true));
});
```

## Generating all keys for all features
This script generates a sig/enc pair of private keys for all supported algorithms you can have if
you enable encryption features on your provider instance.

```js
const { createKeyStore } = require('oidc-provider');
const keystore = createKeyStore();
Promise.all([
  keystore.generate('RSA', 2048, {
    kid: 'sig-rs-0',
    use: 'sig',
  }),
  keystore.generate('RSA', 2048, {
    kid: 'enc-rs-0',
    use: 'enc',
  }),
  keystore.generate('EC', 'P-256', {
    kid: 'sig-ec2-0',
    use: 'sig',
  }),
  keystore.generate('EC', 'P-256', {
    kid: 'enc-ec2-0',
    use: 'enc',
  }),
  keystore.generate('EC', 'P-384', {
    kid: 'sig-ec3-0',
    use: 'sig',
  }),
  keystore.generate('EC', 'P-384', {
    kid: 'enc-ec3-0',
    use: 'enc',
  }),
  keystore.generate('EC', 'P-521', {
    kid: 'sig-ec5-0',
    use: 'sig',
  }),
  keystore.generate('EC', 'P-521', {
    kid: 'enc-ec5-0',
    use: 'enc',
  })
]).then(function () {
  console.log('my JWKS:\n', keystore.toJSON(true));
});
```

## Transforming existing keys from other formats
```js
const { asKey } = require('oidc-provider');
// where input is either a:
// *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
// *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER

// format is either a:
// * 'pkcs8' for a DER encoded (unencrypted!) PKCS8 private key
// * 'spki'  for a DER encoded SPKI public key
// * 'x509'  for a DER encoded PKIX X.509 certificate
// * 'pem'   for a PEM encoded of PKCS8 / SPKI / PKIX
asKey(input, format).then(function(key) {
  console.log('my key in private JWK format:\n', key.toJSON(true));
});
```

## Signing Key Rotation
Following action order is recommended when rotating signing certificates keys on a
distributed deployment with rolling reloads in place.

1. push new keys at the very end of the "keys" array in your JWKS
  - this means the keys will become available for verification should they be encountered but not
  yet used for signing
2. reload all your processes
3. move your new key to the very front of the "keys" array in your JWKS
  - this means the key will be used for signing
4. reload all your processes

[node-jose-library]: https://github.com/cisco/node-jose
[jose-jwk]: https://tools.ietf.org/html/rfc7517
