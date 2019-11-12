# Wildcard support

- built for version: ^6.0.0
- no guarantees this is bug-free, no support will be provided for this, you've been warned, you're on
your own
- if you get caught allowing wildcards in production you'll suffer the consequences

> ⚠️ This violates both the OpenID Connect specification and OAuth 2.0 Security Best Current
> Practice and opens up your Relying Parties as Open Redirectors during many documented OAuth 2.0
> attacks. **Its only practical use-case is for development purposes and as such is not recommended
> for any production deployment.**


## `redirect_uris`

Install the `wildcard` and `psl` packages.

```console
npm i wildcard@^1.1.2
npm i psl@^1.1.33
```

Update whatever file holds your provider, e.g. `index.js` where the provider instance Client
prototype needs to be changed.

```js
const net = require('net');
const { URL } = require('url');

const wildcard = require('wildcard');
const psl = require('psl');
const { InvalidClientMetadata } = Provider.errors;

// defining `redirect_uris` as custom client metadata enables to run additional validations
// here some conditions are applied for "using" wildcards

const provider = new Provider(/* your issuer identifier */, {
  extraClientMetadata: {
    properties: ['redirect_uris'],
    validator(key, value, metadata) {
      if (key === 'redirect_uris') {
        for (const redirectUri of value) {
          if (redirectUri.includes('*')) {
            const { hostname, href } = new URL(redirectUri);

            if (href.split('*').length !== 2) {
              throw new InvalidClientMetadata('redirect_uris with a wildcard may only contain a single one');
            }

            if (!hostname.includes('*')) {
              throw new InvalidClientMetadata('redirect_uris may only have a wildcard in the hostname');
            }

            const test = hostname.replace('*', 'test');

            // checks that the wildcard is for a full subdomain e.g. *.panva.cz, not *suffix.panva.cz
            if (!wildcard(hostname, test)) {
              throw new InvalidClientMetadata('redirect_uris with a wildcard must only match the whole subdomain');
            }

            if (!psl.get(hostname.split('*.')[1])) {
              throw new InvalidClientMetadata('redirect_uris with a wildcard must not match an eTLD+1 of a known public suffix domain');
            }
          }
        }
      }
    },
  },
});

// redirectUriAllowed on a client prototype checks whether a redirect_uri is allowed or not
const { redirectUriAllowed } = provider.Client.prototype;

const hasWildcardHost = (redirectUri) => {
  const { hostname } = new URL(redirectUri);
  return hostname.includes('*');
};

const wildcardMatches = (redirectUri, wildcardUri) => !!wildcard(wildcardUri, redirectUri);

provider.Client.prototype.redirectUriAllowed = function wildcardRedirectUriAllowed(redirectUri) {
  if (!redirectUri.includes('*')) {
    return redirectUriAllowed.call(this, redirectUri);
  }
  const wildcardUris = this.redirectUris.filter(hasWildcardHost);
  return wildcardUris.some(wildcardMatches.bind(undefined, redirectUri));
};
```

## `post_logout_redirect_uris`

Similar to the above with the same recommendation not to use this in any other environment other
than development, the only things that change are metadata property names (`post_logout_redirect_uris`),
client property on which the whitelist is (`postLogoutRedirectUris`) and the client method called
(`postLogoutRedirectUriAllowed`).
