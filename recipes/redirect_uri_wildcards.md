# Wildcard support

- built for version: ^6.0.0
- no guarantees this is bug-free
- if you get caught using this in production you'll go to jail

> ⚠️ This violates both the OpenID Connect specification and OAuth 2.0 Security Best Current
> Practice and opens up your Relying Parties as Open Redirectors during many documented OAuth 2.0
> attacks. **Its only practical use-case is for development purposes and as such is not recommended
> for any production deployment.**


## `redirect_uri`

Install the `wildcard` package.

```console
npm i wildcard@^1.1.2
```

Update whatever file holds your provider, e.g. `index.js` where the provider instance Client
prototype needs to be changed.

```js
const net = require('net');
const { URL } = require('url');

const wildcard = require('wildcard');

const provider = new Provider(/* your configuration */);

const { redirectUriAllowed } = provider.Client.prototype;

const hasWildcardHost = (redirectUri) => {
  const { hostname, href } = new URL(redirectUri);

  // TODO: in addition to this you should not allow wildcard to be the eTLD+1 and/or known
  // multi-tenant hosting such as *.herokuapp.com

  // only one asterisk and in the hostname that is not an IP address
  return !net.isIP(hostname) && href.split('*').length === 2 && hostname.includes('*');
};

const wildcardMatches = (redirectUri, wildcardUri) => !!wildcard(wildcardUri, redirectUri);

provider.Client.prototype.redirectUriAllowed = function wildcardRedirectUriAllowed(redirectUri) {
  if (redirectUriAllowed.call(this, redirectUri)) return true;
  const wildcardUris = this.redirectUris.filter(hasWildcardHost);
  return wildcardUris.some(wildcardMatches.bind(undefined, redirectUri));
};
```

## `post_logout_redirect_uris`

Same as the above with the same recommendation not to use this in any other environment other than
development.

```js
const { postLogoutRedirectUriAllowed } = provider.Client.prototype;

provider.Client.prototype.postLogoutRedirectUriAllowed = function wildcardPostLogoutRedirectUriAllowed(logoutUri) {
  if (postLogoutRedirectUriAllowed.call(this, logoutUri)) return true;
  const wildcardUris = this.postLogoutRedirectUris.filter(hasWildcardHost);
  return wildcardUris.some(wildcardMatches.bind(undefined, logoutUri));
};
```
