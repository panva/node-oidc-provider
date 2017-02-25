# Events

Your oidc-provider instance is an event emitter, `this` is always the instance. In events where `ctx`
(request context) is passed to the listener `ctx.oidc` [OIDCContext](/lib/helpers/oidc_context.js) holds additional details like recognized
parameters, loaded client or session.

| event name | event handler function parameters | Emitted ... |
|---|---|---|
| server_error | (error, ctx) | ... whenever an exception is thrown or promise rejected from   either the Provider or your provided  adapters. If it comes from the library you should probably report it. |
| authorization.accepted | (ctx) | ... with every syntactically correct authorization request pending resolving. |
| interaction.started | (detail, ctx) | ... whenever interaction is being requested from the end-user. |
| interaction.ended | (ctx) | ... whenever interaction has been resolved and the authorization request continues being processed. |
| authorization.success | (ctx) | ... with every successfully completed authorization request. Useful i.e. for collecting metrics or triggering any action you need to execute after succeeded authorization. |
| authorization.error | (error, ctx) | ... whenever a handled error is encountered in the `authorization` endpoint. |
| grant.success | (ctx) | ... with every successful grant request. Useful i.e. for collecting metrics or triggering any action you need to execute after succeeded grant. |
| grant.error | (error, ctx) | ... whenever a handled error is encountered in the `grant` endpoint. |
| certificates.error | (error, ctx) | ... whenever a handled error is encountered in the `certificates` endpoint. |
| discovery.error | (error, ctx) | ... whenever a handled error is encountered in the `discovery` endpoint. |
| introspection.error | (error, ctx) | ... whenever a handled error is encountered in the `introspection` endpoint. |
| revocation.error | (error, ctx) | ... whenever a handled error is encountered in the `revocation` endpoint. |
| registration_create.success | (client, ctx) | ... with every successful client registration request. |
| registration_create.error | (error, ctx) | ... whenever a handled error is encountered in the POST `registration` endpoint. |
| registration_read.error | (error, ctx) | ... whenever a handled error is encountered in the GET `registration` endpoint. |
| registration_update.success | (client, ctx) | ... with every successful update client registration request. |
| registration_update.error | (error, ctx) | ... whenever a handled error is encountered in the PUT `registration` endpoint. |
| registration_delete.success | (client, ctx) | ... with every successful delete client registration request. |
| registration_delete.error | (error, ctx) | ... whenever a handled error is encountered in the DELETE `registration` endpoint. |
| userinfo.error | (error, ctx) | ... whenever a handled error is encountered in the `userinfo` endpoint. |
| check_session.error | (error, ctx) | ... whenever a handled error is encountered in the `check_session` endpoint. |
| end_session.success | (ctx) | ... with every success end session request. |
| end_session.error | (error, ctx) | ... whenever a handled error is encountered in the `end_session` endpoint. |
| webfinger.error | (error, ctx) | ... whenever a handled error is encountered in the `webfinger` endpoint. |
| token.issued | (token) | ... whenever a token is issued. All tokens extending `BaseToken` emit this event. token can be one of `AccessToken`, `AuthorizationCode`, `ClientCredentials`, `RefreshToken`, `InitialAccessToken`, `RegistrationAccessToken`. |
| token.consumed | (token) | ... whenever a token (actually just AuthorizationCode) is consumed. |
| token.revoked | (token) | ... whenever a token is about to be revoked. |
| grant.revoked | (grantId) | ... whenever tokens resulting from a single grant are about to be revoked. `grantId` is uuid formatted string. Use this to cascade the token revocation in cases where your adapter cannot provide this functionality. |
