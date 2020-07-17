# Skipping consent screen

- built for version: ^6.0.0
- no guarantees this is bug-free, no support will be provided for this, you've been warned, you're on
your own
- it is not recommended to have consent-free flows for the obvious issues this poses for native 
applications

Sometimes with your provider you don't need a consent screen.
This use-case might occur if your provider has only *first-party* clients configured.
To achieve that you need to remove `consent` interaction from provider policy configuration:

```js
const {
  interactionPolicy: { base },
} = require('oidc-provider');

const policy = base(); // initialize your own policy from default base policy
policy.remove('consent'); // remove consent Prompt from it


const oidcConfiguration = {
  interactions: {
    policy, // add customized policy here
    // ... rest of the interactions configuration
  },
  // ...rest of the OP configuraton
};
const provider = new Provider(ISSUER, oidcConfiguration); // finally, configure your provider
```

Additionally, if you do remove consent prompt, you will get error when your RPs try to request scopes other than `openid` and `offline_access`.
In order to accomodate those use-cases, you need to provide accepted property in interaction results whenever `interactionFinished` is called.

```js
const details = await provider.interactionDetails(req, res);
// rest of your code...

const result = {
  login: { account: account.accountId },
  consent: { 
    rejectedScopes: [], // array of strings representing rejected scopes, see below
    rejectedClaims: [], // array of strings representing rejected claims, see below
  },
};
const options = { mergeWithLastSubmission: false };
await provider.interactionFinished(req, res, result, options);
```

You should also provide of `rejectedScopes` and `rejectedClaims` in `consent` object in order to prevent scopes/claims being exposed to clients you don't want them to be exposed to.
