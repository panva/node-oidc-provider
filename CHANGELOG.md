# Changelog

Following semver, 1.0.0 will mark the first API stable release and commence of this file,
until then please use the compare views of github for reference.

- https://github.com/panva/node-oidc-provider/compare/v0.10.2...v0.11.0
  - BREAKING: ALL previously issued tokens are incompatible with the new version, the length of the
  tokens is now shorter and does not contain any information about the token context or type, this
  is to make space for Token Integrity feature that brings much faster, cheaper token generation.
  [Read More](#token-integrity)
  - fix: revocation is only possible for client's OWN tokens
  - change: end_session now with user confirmation and optionally without id_token_hint (as per spec)
  - change: session management individual states now in individual cookies rather than one
  - change: configuration.timeouts is removed
  - change: Back-Channel Logout draft implementation bumped from 02 to 03
  - change: dynamic registration related events now include the relevant CRUD verb
  - change: when remember is missing from the resume cookie a transient cookie is issued instead of
  no cookie at all
  - change: errors now use the renderError helper when viewed in a browser environment
  - change: interactionUrl has now ctx bound as this, and as parameter gets the interaction details
  - change: uniqueness has now ctx bound as this
  - change: renderError has now ctx bound as this
  - change: default cookies not signed (faster up and running development)
  - added: Setting defaultHttpOptions on provider instance for external http requests
  - added: Initial Access Token for Dynamic Registration (either fixed string or backed by adapter)
  - added: Update and Delete from RFC7592 - OAuth 2.0 Dynamic Client Registration Management
  Protocol
  - added: Back-Channel Logout session now supported
    - sid claim is available in id tokens when backchannelLogout is enabled
    - unique sid is now stored for each encountered client in a session
  - change: session model
    - new property `authorizations` of type Object now stored with the session, currently can only
    contain sid key, in the future will contain more
  - change: interaction is now requested first time a client is encountered (strategies for this
  coming later)
  - DEPRECATION: provider.get('ModelName') now deprecated, instead use provider.ModelName, ie.
  provider.AccessToken
  - DEPRECATION: provider.addKey now deprecated, prepare your keystores before new call and pass it
  via configuration.keystore
- https://github.com/panva/node-oidc-provider/compare/v0.10.0...0.10.2
  - fix: push nonce from code to refresh token and then id_token upon refresh
  - fix: RFC6749 4.1.2.1 - missing, unrecognized, invalid client_id and redirect_uri handling (consistent no redirect)
- https://github.com/panva/node-oidc-provider/compare/v0.9.0...v0.10.0
  - added: custom discovery property config
  - added: returning distributed and aggregated claims
  - added: Back-Channel Logout draft implementation
  - added: registration.success event
  - added: allow clients for introspections/revocations only (Resource Servers) with no
  authorization flow access
  - added: draft / experimental features now warn upon provider init
  - fix: introspection follows normal/pairwise subject claim of the token's client
  - fix: added client_id_issued_at client property upon registration
- https://github.com/panva/node-oidc-provider/compare/v0.8.1...v0.9.0
  - added: (no)cache headers according to specs
  - fix: consent_required error now returned when consent prompt is not resolved
  - fix: now validates payload of none-signed id_token_hints
  - fix: signed userinfo token expiration
  - fix: unsigned (when id_token_signed_response_alg is not defined, not when none) are now properly
  unsigned, jwe payload is the userinfo response, not a jwt
- https://github.com/panva/node-oidc-provider/compare/v0.7.2...v0.8.1
  - fixed a bug that allowed userinfo and idtoken encrypting clients to pass validation
  - account is configured entirely different now - check examples!
- https://github.com/panva/node-oidc-provider/compare/v0.7.1...v0.7.2
  - fixed a bug that prevented non default client auth strategies to be recognized for introspection
  and revocation
- https://github.com/panva/node-oidc-provider/compare/v0.7.0...v0.7.1
  - fixed a bug that prevented refresh_token grant from issuing an id_token
- https://github.com/panva/node-oidc-provider/compare/v0.6.0...v0.7.0
  - all things `authentication` renamed to `authorization`
- https://github.com/panva/node-oidc-provider/compare/v0.5.0...v0.6.0
- https://github.com/panva/node-oidc-provider/compare/v0.4.0...v0.5.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.1...v0.4.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.0...v0.3.1
- https://github.com/panva/node-oidc-provider/compare/v0.2.0...v0.3.0

## Token Integrity
pre-0.11 all oauth tokens used JWT for serialization and your mandatory RS256 able key for
integrity validation and the string value was > 300 characters long containing the body and signature
part of the JWT with all sensitive information pushed to the header part which only remained in your
storage/adapter.  
Whenever a token would be presented it would be decoded for jti, looked up, and it's signature
validated. This is problematic for providers who want to rotate their signing keys without
invalidating issued tokens and for. You couldn't choose which key is used for integrity check, you
had no control over the alg used, causing tokens to be issued slowly in high concurrency scenarios.  
0.11 by default comes with token integrity disabled, oauth tokens will not be cryptographically
signed and instead just be random values (which is fine for most).  
To enable the extra layer of protection (essentially against someone controlling your tokens via the
storage layer) you just need to pass a jose.JWK.KeyStore as `tokenIntegrity` configuration option.
The first token you push on to this key store will be used to cryptographically sign the oauth tokens
prohibiting any tampering with the payload and header content.
