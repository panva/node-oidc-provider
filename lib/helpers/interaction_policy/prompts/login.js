/* eslint-disable camelcase */

import * as errors from '../../errors.js';
import get from '../../_/get.js';
import instance from '../../weak_cache.js';
import Prompt from '../prompt.js';
import Check from '../check.js';

export default () => new Prompt(
  { name: 'login', requestable: true },

  (ctx) => {
    const { oidc } = ctx;

    return {
      ...(oidc.params.max_age === undefined ? undefined : { max_age: oidc.params.max_age }),
      ...(oidc.params.login_hint === undefined
        ? undefined
        : { login_hint: oidc.params.login_hint }),
      ...(oidc.params.id_token_hint === undefined
        ? undefined
        : { id_token_hint: oidc.params.id_token_hint }),
    };
  },

  new Check('no_session', 'End-User authentication is required', (ctx) => {
    const { oidc } = ctx;
    if (oidc.session.accountId) {
      return Check.NO_NEED_TO_PROMPT;
    }

    return Check.REQUEST_PROMPT;
  }),

  new Check('max_age', 'End-User authentication could not be obtained', (ctx) => {
    const { oidc } = ctx;
    if (oidc.params.max_age === undefined) {
      return Check.NO_NEED_TO_PROMPT;
    }

    if (!oidc.session.accountId) {
      return Check.REQUEST_PROMPT;
    }

    if (oidc.session.past(oidc.params.max_age) && (!ctx.oidc.result || !ctx.oidc.result.login)) {
      return Check.REQUEST_PROMPT;
    }

    return Check.NO_NEED_TO_PROMPT;
  }),

  new Check(
    'id_token_hint',
    'id_token_hint and authenticated subject do not match',
    async (ctx) => {
      const { oidc } = ctx;
      if (oidc.entities.IdTokenHint === undefined) {
        return Check.NO_NEED_TO_PROMPT;
      }

      const { payload } = oidc.entities.IdTokenHint;

      let sub = oidc.session.accountId;
      if (sub === undefined) {
        return Check.REQUEST_PROMPT;
      }

      if (oidc.client.subjectType === 'pairwise') {
        sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(
          ctx,
          sub,
          oidc.client,
        );
      }

      if (payload.sub !== sub) {
        return Check.REQUEST_PROMPT;
      }

      return Check.NO_NEED_TO_PROMPT;
    },
  ),

  new Check(
    'claims_id_token_sub_value',
    'requested subject could not be obtained',
    async (ctx) => {
      const { oidc } = ctx;

      if (
        !oidc.claims.id_token
          || !oidc.claims.id_token.sub
          || !('value' in oidc.claims.id_token.sub)
      ) {
        return Check.NO_NEED_TO_PROMPT;
      }

      let sub = oidc.session.accountId;
      if (sub === undefined) {
        return Check.REQUEST_PROMPT;
      }

      if (oidc.client.subjectType === 'pairwise') {
        sub = await instance(oidc.provider).configuration('pairwiseIdentifier')(
          ctx,
          sub,
          oidc.client,
        );
      }

      if (oidc.claims.id_token.sub.value !== sub) {
        return Check.REQUEST_PROMPT;
      }

      return Check.NO_NEED_TO_PROMPT;
    },
    ({ oidc }) => ({ sub: oidc.claims.id_token.sub }),
  ),

  new Check(
    'essential_acrs',
    'none of the requested ACRs could not be obtained',
    (ctx) => {
      const { oidc } = ctx;
      const request = get(oidc.claims, 'id_token.acr', {});

      if (!request || !request.essential || !request.values) {
        return Check.NO_NEED_TO_PROMPT;
      }

      if (!Array.isArray(oidc.claims.id_token.acr.values)) {
        throw new errors.InvalidRequest('invalid claims.id_token.acr.values type');
      }

      if (request.values.includes(oidc.acr)) {
        return Check.NO_NEED_TO_PROMPT;
      }

      return Check.REQUEST_PROMPT;
    },
    ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
  ),

  new Check(
    'essential_acr',
    'requested ACR could not be obtained',
    (ctx) => {
      const { oidc } = ctx;
      const request = get(oidc.claims, 'id_token.acr', {});

      if (!request || !request.essential || !request.value) {
        return Check.NO_NEED_TO_PROMPT;
      }

      if (request.value === oidc.acr) {
        return Check.NO_NEED_TO_PROMPT;
      }

      return Check.REQUEST_PROMPT;
    },
    ({ oidc }) => ({ acr: oidc.claims.id_token.acr }),
  ),
);
