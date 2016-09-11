Following semver, 1.0.0 will mark the first API stable release and commence of this file,
until then please use the compare views of github for reference.



- master
  - changed: Back-Channel Logout draft implementation bumped from 02 to 03
  - added: Initial Access Token for Dynamic Registration (either fixed string or backed by adapter)
  - added: Update and Delete from RFC7592 - OAuth 2.0 Dynamic Client Registration Management
  Protocol
  - change: dynamic registration related events now include the relevant CRUD verb
  - BREAKING CHANGE: `registration_access_token`s of previously registered clients from dynamic
  registration are now invalid, create new ones with
  `new RegistrationAccessToken({ clientId }).save()` this, when resolved, returns the string value
  of a new registration_access_token
  - change: when remember is missing from the resume cookie a transient cookie is issued instead of
  no cookie at all
  - errors now use the renderError helper when viewed in a browser environment
  - Back-Channel Logout session now supported
    - sid claim is available in id tokens when backchannelLogout is enabled
    - unique sid is now stored for each encountered client in a session
  - session model changes
    - new property `authorizations` of type Object now stored with the session, currently can only
    contain sid key, in the future will contain more
  - Interaction is now requested first time a client is encountered (strategies for this coming later)


- feature/change-token-format
  - DEPRECATION: provider.get('ModelName') now deprecated, instead use provider.ModelName, ie.
  provider.AccessToken
  - DEPRECATION: provider.addKey now deprecated, prepare your keystores before new call and pass it
  via configuration.keystore
  - BREAKING: ALL previously issued tokens are incompatible with the new version, the length of the
  tokens is now shorter and does not contain any information about the token context or type
  - fix: revocation is only possible for client's OWN tokens

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
