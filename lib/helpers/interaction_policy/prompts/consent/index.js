/* eslint-disable camelcase */

const omitBy = require('../../../_/omit_by');
const Prompt = require('../../prompt');

const client_not_authorized = require('./client_not_authorized');
const native_client_prompt = require('./native_client_prompt');
const scopes_missing = require('./scopes_missing');
const claims_missing = require('./claims_missing');

module.exports = () => new Prompt(
  { name: 'consent', requestable: true },

  (ctx) => {
    const { oidc } = ctx;

    const acceptedScopes = oidc.session.acceptedScopesFor(oidc.params.client_id);
    const rejectedScopes = oidc.session.rejectedScopesFor(oidc.params.client_id);
    const acceptedClaims = oidc.session.acceptedClaimsFor(oidc.params.client_id);
    const rejectedClaims = oidc.session.rejectedClaimsFor(oidc.params.client_id);

    const details = {
      scopes: {
        new: [...oidc.requestParamScopes]
          .filter((x) => !acceptedScopes.has(x) && !rejectedScopes.has(x)),
        accepted: [...acceptedScopes],
        rejected: [...rejectedScopes],
      },
      claims: {
        new: [...oidc.requestParamClaims]
          .filter((x) => !acceptedClaims.has(x) && !rejectedClaims.has(x)),
        accepted: [...acceptedClaims],
        rejected: [...rejectedClaims],
      },
    };

    return omitBy(details, (val) => val === undefined);
  },

  client_not_authorized(),
  native_client_prompt(),
  scopes_missing(),
  claims_missing(),
);
