# Skipping consent screen

Sometimes with your provider you don't need a consent screen.
This use-case might occur if your provider has only *first-party* clients configured.
To achieve that you need to remove `consent` interaction from provider policy configuration:

```js
const {
  interactionPolicy: { base }
} = require('oidc-provider')

const policy = base() // initialize your own policy from default base policy
policy.remove('consent') // remove consent Prompt from it


const oidcConfiguration = {
  interactions: {
    policy // add customized policy here
    // ... rest of the interactions configuration
  }
  // ...rest of the OP configuraton
}
const provider = new Provider(ISSUER, oidcConfiguration) // finally, configure your provider
```

Additionally, if you do remove consent prompt, you will get error when your RPs try to request scopes other than `openid` and `offline_access`.
In order to accomodate those use-cases, you need to provide accepted property in interaction results whenever `interactionFinished` is called.

```js
const details = await provider.interactionDetails(req, res)
// rest of your code...

const result = {
  select_account: {},
  login: { account: account.accountId },
  consent: { accepted: [details.params.scope.split(' ').filter(scope => WHITELISTED_SCOPES.includes(scope))] }
}
const options = { mergeWithLastSubmission: false }
await provider.interactionFinished(req, res, result, options)
```

You should also provide `WHITELISTED_SCOPES` to above code based on `clientId` in order to prevent scopes being exposed to clients you don't want them to be exposed to.
You can also blacklist scopes by adding them to `consent.rejectedScopes` key, or blacklist claims by adding them to `consent.rejectedClaims` key in order to prevent them from being issued.
