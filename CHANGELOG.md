Following semver, 1.0.0 will mark the first API stable release and commence of this file,
until then please use the compare views of github for reference.

- https://github.com/panva/node-oidc-provider/compare/v0.8.1...v0.9.0
  - added: (no)cache headers according to specs
  - fix: consent_required error now returned when consent prompt is not resolved
  - fix: now validates payload of none-signed id_token_hints
  - fix: signed userinfo token expiration
  - fix: unsigned (when id_token_signed_response_alg is not defined, not when none) are now properly unsigned, jwe payload is the userinfo response, not a jwt
- https://github.com/panva/node-oidc-provider/compare/v0.7.2...v0.8.1
  - fixed a bug that allowed userinfo and idtoken encrypting clients to pass validation
  - account is configured entirely different now - check examples!
- https://github.com/panva/node-oidc-provider/compare/v0.7.1...v0.7.2
  - fixed a bug that prevented non default client auth strategies to be recognized for introspection and revocation
- https://github.com/panva/node-oidc-provider/compare/v0.7.0...v0.7.1
  - fixed a bug that prevented refresh_token grant from issuing an id_token
- https://github.com/panva/node-oidc-provider/compare/v0.6.0...v0.7.0
  - all things `authentication` renamed to `authorization`
- https://github.com/panva/node-oidc-provider/compare/v0.5.0...v0.6.0
- https://github.com/panva/node-oidc-provider/compare/v0.4.0...v0.5.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.1...v0.4.0
- https://github.com/panva/node-oidc-provider/compare/v0.3.0...v0.3.1
- https://github.com/panva/node-oidc-provider/compare/v0.2.0...v0.3.0
