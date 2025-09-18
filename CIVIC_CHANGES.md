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

4. Refresh Token Tolerance Configuration (`refreshTolerance`)
   The library now supports configurable refresh token tolerance settings to address multi-tab/session scenarios where clients may have cached tokens that become invalid due to rotation or revocation by other sessions.

   ```js
   new Provider(issuer, {
     refreshTolerance: {
       gracePeriodSeconds: 10, // Allow consumed tokens to be valid for 10 more seconds
       revokeEntireGrantAfterGracePeriod: true, // Revoke entire grant if token used beyond grace period
     },
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
     refreshTolerance: {
       gracePeriodSeconds: 15, // 15 second grace period
       revokeEntireGrantAfterGracePeriod: true, // Default security behavior
     },
     rotateRefreshToken: true, // Enable token rotation
   })
   ```

5. Refresh Token Grace Period Grant Revocation Control (`refreshTolerance.revokeEntireGrantAfterGracePeriod`)
   This configuration flag controls the behavior when a refresh token is presented beyond its grace period, providing granular control over security responses to out-of-grace token usage.

   ```js
   new Provider(issuer, {
     refreshTolerance: {
       gracePeriodSeconds: 10, // Enable grace period
       revokeEntireGrantAfterGracePeriod: false, // Only invalidate specific token
     },
   })
   ```

   **Behavior modes:**
   - **`true` (default)**: When a consumed token is used beyond its grace period, the entire grant and all associated tokens are revoked for maximum security
   - **`false`**: When a consumed token is used beyond its grace period, only that specific token is invalidated while other tokens in the grant remain valid

   **Security considerations:**
   - **Default `true` provides maximum security**: Assumes token compromise when presented beyond grace period, triggering full grant revocation
   - **Setting to `false` reduces security**: Potentially compromised tokens don't trigger full grant revocation, allowing other tokens to remain valid
   - **Recommendation**: Keep default value of `true` unless specific use cases require token-level granular control and security implications are well understood

   **Use cases for `false` setting:**
   - Applications with very long-lived grants containing many tokens
   - Scenarios where token-level invalidation is preferred over grant-level revocation
   - Development/testing environments where less aggressive revocation is desired

   **Usage Example:**
   ```js
   // Granular token invalidation mode
   new Provider(issuer, {
     refreshTolerance: {
       gracePeriodSeconds: 10, // 10 second grace period
       revokeEntireGrantAfterGracePeriod: false, // Only invalidate specific token
     },
     rotateRefreshToken: true,
   })
   ```

   **Important**: This setting only affects behavior when tokens are used beyond their grace period. Grace period functionality itself (allowing consumed tokens within the grace period) remains unchanged regardless of this setting.

6. Refresh Token Grace Period Event (`refresh_token.reused_within_grace_period`)
   The provider emits a special event whenever a consumed refresh token is successfully reused within its grace period, allowing applications to track and monitor this behavior for security and auditing purposes.

   **Event Details:**
   - **Event Name**: `refresh_token.reused_within_grace_period`
   - **When Emitted**: When a consumed refresh token is presented and accepted because it's still within its grace period
   - **Event Arguments**: `(ctx, refreshToken)` where `ctx` is the request context and `refreshToken` is the token instance

   **Usage Example:**
   ```js
   const provider = new Provider(issuer, {
     refreshTolerance: {
       gracePeriodSeconds: 10, // Enable grace period
       revokeEntireGrantAfterGracePeriod: true, // Default behavior
     },
   });

   // Listen for grace period reuse events
   provider.on('refresh_token.reused_within_grace_period', (ctx, refreshToken) => {
     console.log('Refresh token reused within grace period', {
       clientId: ctx.oidc.client.clientId,
       accountId: refreshToken.accountId,
       grantId: refreshToken.grantId,
       consumedAt: new Date(refreshToken.consumed * 1000),
       userAgent: ctx.get('user-agent'),
       ipAddress: ctx.ip,
     });
   });
   ```

   **Use Cases:**
   - **Security Monitoring**: Track potential multi-tab/session conflicts or suspicious token reuse patterns
   - **Analytics**: Monitor grace period effectiveness and frequency of usage
   - **Alerting**: Set up alerts for unusual grace period usage patterns
   - **Audit Logging**: Maintain detailed logs of all grace period token reuse for compliance

   **Event Properties:**
   - Only emitted when `refreshTolerance.gracePeriodSeconds` is configured and greater than 0
   - Not emitted for tokens that are reused beyond their grace period (those trigger errors instead)
   - Provides full context about the request and token for comprehensive logging

7. Additional Cookie Clearing Paths (`cookies.clearCookiesAtAdditionalPaths`)
   The library now supports clearing cookies at additional paths when the auth server clears cookies, addressing scenarios where cookies may have been set by other components (e.g., login applications) at different paths.

   ```js
   new Provider(issuer, {
     cookies: {
       clearCookiesAtAdditionalPaths: ['/login', '/auth'],
     },
   })
   ```

   **Problem Solved:**
   Auth server cookies are sometimes set for different paths (like `/login` for the login application) and may cause problems with subsequent logins if not properly cleared when the auth server clears its own cookies.

   **How it works:**
   - When the auth server calls `clearAllCookies()`, it will clear cookies at the default path as usual
   - Additionally, it will clear the same cookies (`_session`, `_interaction`, `_interaction_resume`) at each path specified in `clearCookiesAtAdditionalPaths`
   - This ensures cookies set by other applications at different paths don't interfere with fresh authentication flows

   **Use Cases:**
   - Multi-application auth systems where different components set cookies at different paths
   - Login applications that set cookies at `/login` path
   - Preventing cookie interference between authentication sessions

   **Security Considerations:**
   - This feature only affects cookie clearing, not cookie setting or reading behavior
   - No negative security impact as it only clears more cookies, not fewer
   - Helps prevent session state pollution across different application paths

   **Usage Example:**
   ```js
   // Clear cookies at both default path and login app path
   new Provider(issuer, {
     cookies: {
       clearCookiesAtAdditionalPaths: ['/login'],
     },
   })
   ```

   **OAuth/OIDC Specification Compliance:**
   This is a cookie management enhancement that doesn't affect OAuth/OIDC protocol compliance. It's an implementation detail for proper session cleanup in multi-component authentication systems.

8. Relaxed Implicit Grant Requirement (`relaxImplicitGrantRequirement`)
   The library now supports relaxing the requirement that clients with 'id_token' or 'token' in their response_types must include 'implicit' in their grant_types, allowing clients to register with implicit flow response types while only using authorization code flow.

   ```js
   new Provider(issuer, {
     relaxImplicitGrantRequirement: true, // Allow response types without implicit grant
   })
   ```

   **Problem Solved:**
   The OAuth 2.0 specification states that authorization servers MAY reject or replace client metadata values. Some clients want to indicate they can accept implicit flow responses (id_token, token) but prefer to only use authorization code flow for security reasons.
   i.e. clients can say: "I accept responses one of which can only be obtained via the implicit flow, but I don't want to use the implicit flow, I only want to use auth code flow"

   **How it works:**
   - When set to `false` (default): Standard OAuth 2.0 validation applies - clients with 'id_token' or 'token' response types MUST include 'implicit' grant type
   - When set to `true`: Clients can register with 'id_token' or 'token' response types without requiring 'implicit' grant type
   - This allows clients to signal acceptance of implicit response types while restricting themselves to authorization code flow only

   **Security Considerations:**
   - **Positive security impact**: Allows clients to avoid enabling implicit grant type while still indicating support for implicit response types
   - **No negative security impact**: Clients that don't want implicit flow can avoid it entirely while maintaining response type compatibility
   - **Maintains client control**: Individual clients can choose their preferred grant types without being forced into implicit flow

   **OAuth/OIDC Specification Compliance:**
   This feature leverages OAuth 2.0 RFC 6749 Section 2 which states: "The authorization server MAY reject or replace any of the client's requested metadata values submitted during the registration and substitute them with suitable values." This is a minor relaxation of typical validation rules that prioritizes security by allowing clients to avoid implicit grant while maintaining response type flexibility.