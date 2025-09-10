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
       async shouldWriteCookies(ctx) {
         // Custom logic to determine if cookies should be written
         // Example: Don't write cookies for requests with Civic SDK state parameters
         const stateParam = ctx.query?.state || ctx.oidc?.params?.state;
         return !isCivicStateParam(stateParam); // Your custom logic here
       }
     }
   })
   ```

   When `shouldWriteCookies` is not provided, the library defaults to checking `!cookies.doNotSet` for backward compatibility.

   If `shouldWriteCookies` returns false, any existing cookies from previous sessions are also deleted, in addition to not writing cookies for the current session.

4. Refresh Token Grace Period (`refreshTokenGracePeriodSeconds`)
   The library now supports a configurable grace period for refresh tokens to address multi-tab/session scenarios where clients may have cached tokens that become invalid due to rotation or revocation by other sessions.

   ```js
   new Provider(issuer, {
     refreshTokenGracePeriodSeconds: 10, // Allow consumed tokens to be valid for 10 more seconds
   })
   ```

   **How it works:**
   - When set to a positive value, consumed or revoked refresh tokens remain valid for the specified duration
   - During token rotation, consumed tokens can still be used within the grace period to issue new access tokens
   - Helps prevent authentication errors in multi-tab scenarios where one tab refreshes tokens while others are still using the original token
   - Maintains backward compatibility: when undefined or 0, strict OAuth security behavior is preserved

   **Security considerations:**
   - Extends the attack window for compromised refresh tokens by the grace period duration
   - Allows multiple valid tokens for the same grant during the grace period
   - **Recommendation**: Use conservative values (5-30 seconds) and only when multi-session token conflicts are observed
   - Default value of `undefined` maintains strict OAuth security behavior without any grace period

   **OAuth/OIDC Specification Compliance:**
   This feature represents a minor deviation from RFC 6749 Section 6, which states refresh tokens should be single-use. The implementation prioritizes practical multi-session usability over strict specification compliance. This is documented as a **non-standard extension** that trades strict spec compliance for improved user experience in multi-tab scenarios.

   **Usage Example:**
   ```js
   // Conservative production setting
   new Provider(issuer, {
     refreshTokenGracePeriodSeconds: 15, // 15 second grace period
     rotateRefreshToken: true, // Enable token rotation
   })
   ```