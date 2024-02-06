# Debugging and built-in events

- built for version: ^8.0.0
- no guarantees this is bug-free

To get started with event listeners here is an example, which can be further expanded.

Usecases for this include:

- logging
- providing an audit trail
- hook for analytics

This example subscribes to all [events](../docs/events.md) the oidc-provider emits.

## Add an event listeners handler



```diff
+ import subscribe from './events-listeners.js'
...
const provider = new Provider(ISSUER, configuration);
+ subscribe(provider);
...
```

<details>
<summary>Example events-listeners.js implementation</summary>

```js
import debug from 'debug'

const prefix = 'oidc-provider:events:'

/**
 * Subscribe to all oidc-provider events.
 * 
 */
export default function subscribe(provider) {
  const eventHandlers = [
    ['access_token.destroyed', onAccessTokenDestroyed],
    ['access_token.saved', onAccessTokenSaved],
    ['access_token.issued', onAccessTokenIssued],
    ['authorization_code.consumed', onAuthorizationCodeConsumed],
    ['authorization_code.destroyed', onAuthorizationCodeDestroyed],
    ['authorization_code.saved', onAuthorizationCodeSaved],
    ['authorization.accepted', onAuthorizationAccepted],
    ['authorization.error', onAuthorizationError],
    ['authorization.success', onAuthorizationSuccess],
    ['backchannel.error', onBackchannelError],
    ['backchannel.success', onBackchannelSuccess],
    ['jwks.error', onJwksError],
    ['client_credentials.destroyed', onClientCredentialsDestroyed],
    ['client_credentials.saved', onClientCredentialsSaved],
    ['client_credentials.issued', onClientCredentialsIssued],
    ['device_code.consumed', onDeviceCodeConsumed],
    ['device_code.destroyed', onDeviceCodeDestroyed],
    ['device_code.saved', onDeviceCodeSaved],
    ['discovery.error', onDiscoveryError],
    ['end_session.error', onEndSessionError],
    ['end_session.success', onEndSessionSuccess],
    ['grant.error', onGrantError],
    ['grant.revoked', onGrantRevoked],
    ['grant.success', onGrantSuccess],
    ['initial_access_token.destroyed', onInitialAccessTokenDestroyed],
    ['initial_access_token.saved', onInitialAccessTokenSaved],
    ['interaction.destroyed', onInteractionDestroyed],
    ['interaction.ended', onInteractionEnded],
    ['interaction.saved', onInteractionSaved],
    ['interaction.started', onInteractionStarted],
    ['introspection.error', onIntrospectionError],
    ['replay_detection.destroyed', onReplayDetectionDestroyed],
    ['replay_detection.saved', onReplayDetectionSaved],
    ['pushed_authorization_request.error', onPushedAuthorizationRequestError],
    ['pushed_authorization_request.success', onPushedAuthorizationRequestSuccess],
    ['pushed_authorization_request.destroyed', onPushedAuthorizationRequestDestroyed],
    ['pushed_authorization_request.saved', onPushedAuthorizationRequestSaved],
    ['refresh_token.consumed', onRefreshTokenConsumed],
    ['refresh_token.destroyed', onRefreshTokenDestroyed],
    ['refresh_token.saved', onRefreshTokenSaved],
    ['registration_access_token.destroyed', onRegistrationAccessTokenDestroyed],
    ['registration_access_token.saved', onRegistrationAccessTokenSaved],
    ['registration_create.error', onRegistrationCreateError],
    ['registration_create.success', onRegistrationCreateSuccess],
    ['registration_delete.error', onRegistrationDeleteError],
    ['registration_delete.success', onRegistrationDeleteSuccess],
    ['registration_read.error', onRegistrationReadError],
    ['registration_update.error', onRegistrationUpdateError],
    ['registration_update.success', onRegistrationUpdateSuccess],
    ['revocation.error', onRevocationError],
    ['server_error', onServerError],
    ['session.destroyed', onSessionDestroyed],
    ['session.saved', onSessionSaved],
    ['userinfo.error', onUserinfoError]
  ]

  eventHandlers.map(([eventName, listener]) => {
    const eventDebug = debug(`${prefix}${event}`)
    provider.on(eventName, (...args) => {
      // we detect here when ctx arg is passed so we skip writing ctx argument when debugging, 
      // since it will contain koa request, and can bloat our stdout easily
      eventDebug(...args.filter(arg => !arg.req))
      // finally, we call our listener function that is one of the functions defined bellow
      listener(...args)
    })
  })
}

/**
 * @event access_token.destroyed
 */
function onAccessTokenDestroyed(...args) {}

/**
 * @event access_token.saved
 */
function onAccessTokenSaved(...args) {}

/**
 * @event access_token.issued
 */
function onAccessTokenIssued(...args) {}

/**
 * @event authorization_code.consumed
 */
function onAuthorizationCodeConsumed(...args) {}

/**
 * @event authorization_code.destroyed
 */
function onAuthorizationCodeDestroyed(...args) {}

/**
 * @event authorization_code.saved  
 */
function onAuthorizationCodeSaved(...args) {}

/**
 * @event authorization.accepted
 */
function onAuthorizationAccepted(...args) {}

/**
 * @event authorization.error
 */
function onAuthorizationError(...args) {}

/**
 * @event authorization.success
 */
function onAuthorizationSuccess(...args) {}

/**
 * @event backchannel.error
 */
function onBackchannelError(...args) {}

/**
 * @event backchannel.success
 */
function onBackchannelSuccess(...args) {}

/**
 * @event jwks.error
 */
function onJwksError(...args) {}

/**
 * @event client_credentials.destroyed
 */
function onClientCredentialsDestroyed(...args) {}

/**
 * @event client_credentials.saved
 */
function onClientCredentialsSaved(...args) {}

/**
 * @event client_credentials.issued
 */
function onClientCredentialsIssued(...args) {}

/**
 * @event device_code.consumed
 */
function onDeviceCodeConsumed(...args) {}

/**
 * @event device_code.destroyed
 */
function onDeviceCodeDestroyed(...args) {}

/**
 * @event device_code.saved
 */
function onDeviceCodeSaved(...args) {}

/**
 * @event discovery.error
 */
function onDiscoveryError(...args) {}

/**
 * @event end_session.error
 */
function onEndSessionError(...args) {}

/**
 * @event end_session.success
 */
function onEndSessionSuccess(...args) {}

/**
 * @event grant.error
 */
function onGrantError(...args) {}

/**
 * @event grant.revoked
 */
function onGrantRevoked(...args) {}

/**
 * @event grant.success
 */
function onGrantSuccess(...args) {}

/**
 * @event initial_access_token.destroyed
 */
function onInitialAccessTokenDestroyed(...args) {}

/**
 * @event initial_access_token.saved
 */
function onInitialAccessTokenSaved(...args) {}

/**
 * @event interaction.destroyed
 */
function onInteractionDestroyed(...args) {}

/**
 * @event interaction.ended
 */
function onInteractionEnded(...args) {}

/**
 * @event interaction.saved
 */
function onInteractionSaved(...args) {}

/**
 * @event interaction.started
 */
function onInteractionStarted(...args) {}

/**
 * @event introspection.error
 */
function onIntrospectionError(...args) {}

/**
 * @event replay_detection.destroyed
 */
function onReplayDetectionDestroyed(...args) {}

/**
 * @event replay_detection.saved
 */
function onReplayDetectionSaved(...args) {}

/**
 * @event pushed_authorization_request.error
 */
function onPushedAuthorizationRequestError(...args) {}

/**
 * @event pushed_authorization_request.success
 */
function onPushedAuthorizationRequestSuccess(...args) {}

/**
 * @event pushed_authorization_request.destroyed
 */
function onPushedAuthorizationRequestDestroyed(...args) {}

/**
 * @event pushed_authorization_request.saved
 */
function onPushedAuthorizationRequestSaved(...args) {}

/**
 * @event refresh_token.consumed
 */
function onRefreshTokenConsumed(...args) {}

/**
 * @event refresh_token.destroyed
 */
function onRefreshTokenDestroyed(...args) {}

/**
 * @event refresh_token.saved
 */
function onRefreshTokenSaved(...args) {}

/**
 * @event registration_access_token.destroyed
 */
function onRegistrationAccessTokenDestroyed(...args) {}

/**
 * @event registration_access_token.saved
 */
function onRegistrationAccessTokenSaved(...args) {}

/**
 * @event registration_create.error
 */
function onRegistrationCreateError(...args) {}

/**
 * @event registration_create.success
 */
function onRegistrationCreateSuccess(...args) {}

/**
 * @event registration_delete.error
 */
function onRegistrationDeleteError(...args) {}

/**
 * @event registration_delete.success
 */
function onRegistrationDeleteSuccess(...args) {}

/**
 * @event registration_read.error
 */
function onRegistrationReadError(...args) {}

/**
 * @event registration_update.error
 */
function onRegistrationUpdateError(...args) {}

/**
 * @event registration_update.success
 */
function onRegistrationUpdateSuccess(...args) {}

/**
 * @event revocation.error
 */
function onRevocationError(...args) {}

/**
 * @event server_error
 */
function onServerError(...args) {}

/**
 * @event session.destroyed
 */
function onSessionDestroyed(...args) {}

/**
 * @event session.saved
 */
function onSessionSaved(...args) {}

/**
 * @event userinfo.error
 */
function onUserinfoError(...args) {}
```

</details>

## How to debug any event triggered from oidc-provider?

- Start server with `DEBUG=oidc-provider:*` - to simply include all events subscribed by the example above as well as built-in debug events
- debug individual events, like `DEBUG=oidc-provider:events:access_token.destroyed`
- or for several selected individual events i.e. `DEBUG=oidc-provider:events:access_token.destroyed,oidc-provider:events:access_token.saved`
- or use regex for all events of a single group like access_token using wildcard i.e. `DEBUG=oidc-provider:events:access_token.*`
- or for several groups of events using wildcards i.e. `DEBUG=oidc:event:interaction.*,oidc:event:authorization.*`
