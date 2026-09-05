/**
 * Grant implementation helpers for custom grant types.
 *
 * This module is not covered by semantic versioning conventions. Its exports,
 * signatures, and behavior may change in any release.
 */

// TODO(10.x): explicitly package-export this subpath so it remains accessible
// after other `lib/*` deep imports are encapsulated. This does not bring the
// subpath under semantic versioning conventions.

export {
  consumeGrantSource,
  findAccount,
  findGrantSource,
  validateGrant,
} from './grant_source.js';
export {
  checkDpopRequired,
  checkMtlsCert,
} from './sender_constraints.js';
export { default as validateDpop, checkDpopReplay } from './validate_dpop.js';
export {
  applyAuthorizationDetails,
  resolveAndApplyResource,
  resolveRequestedResources,
  validateClientScope,
} from './grant_authorization.js';
export {
  applyRefreshTokenBindings,
  shouldIssueRefreshToken,
} from './grant_refresh_token.js';
export { buildTokenResponse } from './grant_response.js';
