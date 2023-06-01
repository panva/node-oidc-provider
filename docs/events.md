# Events

Your oidc-provider instance is an event emitter, in the event handlers `this` is always the
Provider instance. In events where
`ctx` (request context) is passed to the listener `ctx.oidc`
[OIDCContext](/lib/helpers/oidc_context.js) holds additional details like recognized parameters,
loaded client or session.

| event name | event handler function parameters | Emitted .. |
|---|---|---|
| `access_token.destroyed` | `(token)` | ... whenever an access token is destroyed |
| `access_token.saved` | `(token)` | ... whenever an opaque access token is saved |
| `access_token.issued` | `(token)` | ... whenever a structured access token is issued |
| `authorization_code.consumed` | `(code)` | ... whenever an authorization code is consumed |
| `authorization_code.destroyed` | `(code)` | ... whenever an authorization code is destroyed |
| `authorization_code.saved` | `(code)` | ... whenever an authorization code is saved |
| `authorization.accepted` | `(ctx)` | ... with every syntactically correct authorization request pending resolving |
| `authorization.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `authorization_endpoint` |
| `authorization.success` | `(ctx)` | ... with every successfully completed authorization request |
| `backchannel.error` | `(ctx, error, client, accountId, sid)` | ... whenever an error is encountered for a client during backchannel-logout |
| `backchannel.success` | `(ctx, client, accountId, sid)` | ... whenever a client is successfully notified about logout through backchannel-logout features |
| `jwks.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `jwks_uri` |
| `client_credentials.destroyed` | `(token)` | ... whenever client credentials token is destroyed |
| `client_credentials.saved` | `(token)` | ... whenever an opaque client credentials token is saved |
| `client_credentials.issued` | `(token)` | ... whenever a structured client credentials token is issued |
| `device_code.consumed` | `(code)` | ... whenever a device code is consumed |
| `device_code.destroyed` | `(code)` | ... whenever a device code is destroyed |
| `device_code.saved` | `(code)` | ... whenever a device code is saved |
| `discovery.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `/.well-known/openid-configuration` endpoint |
| `end_session.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `end_session` endpoint |
| `end_session.success` | `(ctx)` | ... with every success end session request |
| `grant.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `token_endpoint` |
| `grant.revoked` | `(ctx, grantId)` | ... whenever tokens resulting from a single grant are about to be revoked. `grantId` is a random string. Use this to cascade the token revocation in cases where your adapter cannot provide this functionality |
| `grant.success` | `(ctx)` | ... with every successful grant request. Useful i.e. for collecting metrics or triggering any action you need to execute after succeeded grant |
| `initial_access_token.destroyed` | `(token)` | ... whenever inital access token is destroyed |
| `initial_access_token.saved` | `(token)` | ... whenever inital access token is saved |
| `interaction.destroyed` | `(interaction)` | ... whenever interaction session is destroyed |
| `interaction.ended` | `(ctx)` | ... whenever interaction has been resolved and the authorization request continues being processed |
| `interaction.saved` | `(interaction)` | ... whenever interaction session is saved |
| `interaction.started` | `(ctx, prompt)` | ... whenever interaction is being requested from the end-user |
| `introspection.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `introspection_endpoint` |
| `replay_detection.destroyed` | `(token)` | ... whenever a replay detection object is destroyed |
| `replay_detection.saved` | `(token)` | ... whenever a replay detection object is saved |
| `pushed_authorization_request.error` | `(ctx, error)` | ... whenever a handled error is encountered in the POST `pushed_authorization_request` endpoint |
| `pushed_authorization_request.success` | `(ctx, client)` | ... with every successful request object endpoint response |
| `pushed_authorization_request.destroyed` | `(token)` | ... whenever a pushed authorization request object is destroyed |
| `pushed_authorization_request.saved` | `(token)` | ... whenever a pushed authorization request object is saved |
| `refresh_token.consumed` | `(token)` | ... whenever a refresh token is consumed |
| `refresh_token.destroyed` | `(token)` | ... whenever a refresh token is destroyed |
| `refresh_token.saved` | `(token)` | ... whenever a refresh token is saved |
| `registration_access_token.destroyed` | `(token)` | ... whenever registration access token is destroyed |
| `registration_access_token.saved` | `(token)` | ... whenever registration access token is saved |
| `registration_create.error` | `(ctx, error)` | ... whenever a handled error is encountered in the POST `registration_endpoint` |
| `registration_create.success` | `(ctx, client)` | ... with every successful client registration request |
| `registration_delete.error` | `(ctx, error)` | ... whenever a handled error is encountered in the DELETE `registration_endpoint` |
| `registration_delete.success` | `(ctx, client)` | ... with every successful delete client registration request |
| `registration_read.error` | `(ctx, error)` | ... whenever a handled error is encountered in the GET `registration_endpoint` |
| `registration_update.error` | `(ctx, error)` | ... whenever a handled error is encountered in the PUT `registration_endpoint` |
| `registration_update.success` | `(ctx, client)` | ... with every successful update client registration request |
| `revocation.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `revocation_endpoint` |
| `server_error` | `(ctx, error)` | ... whenever an exception is thrown or promise rejected from   either the Provider or your provided  adapters. If it comes from the library you should probably report it |
| `session.destroyed` | `(session)` | ... whenever session is destroyed |
| `session.saved` | `(session)` | ... whenever session is saved |
| `userinfo.error` | `(ctx, error)` | ... whenever a handled error is encountered at the `userinfo_endpoint` |
