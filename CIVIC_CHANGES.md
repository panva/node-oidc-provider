# Civic-specific changes
This is a Civic-specific fork of node-oidc provider containing the following changes:

1. Setting `cookies.enableCookielessFallback: true` in config will cause oidc-provider to ignore the session and interaction cookies, and instead read the interaction ID from the path parameters, and load the session from there.
This is marginally less secure because the auth server can no longer trust that the interaction ID originated from its own domain. However, taking advantage of this would mean brute forcing an interaction ID.
We need to allow this in order to support iframe mode, which has cross-origin restrictions that prevent the auth server cookies from working correctly in all browsers.
With only this flag set, the cookies will still be set by the auth server, and checked if they are sent in subsequent requests. They just won't be required, i.e. if no cookies are sent we fall back to the path parameter.

2. Setting `cookies.doNotSet = true` in addition to `enableCookielessFallback` takes this a step further by not setting the cookies at all. In this mode, no auth-server related cookies will appear in the browser at all.

3. Configurable cookie writing via `cookies.shouldWriteCookies` function
   The library now supports a configurable approach for determining when cookies should be written. You can now pass a `shouldWriteCookies` function in the cookie configuration:

   ```js
   new Provider(issuer, {
     cookies: {
       enableCookielessFallback: true,
       shouldWriteCookies(ctx) {
         // Custom logic to determine if cookies should be written
         // Example: Don't write cookies for requests with Civic SDK state parameters
         const stateParam = ctx.query?.state || ctx.oidc?.params?.state;
         return !isCivicStateParam(stateParam); // Your custom logic here
       }
     }
   })
   ```

   When `shouldWriteCookies` is not provided, the library defaults to checking `!cookies.doNotSet` for backward compatibility.