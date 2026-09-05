import {
  InvalidGrant, InvalidRequest,
} from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import constantEquals from '../../helpers/constant_equals.js';
import {
  checkMtlsCert,
  checkDpopRequired,
  issueTokens,
} from '../../helpers/grant_common.js';

export const gty = 'pre_authorized_code';

export const handler = async function preAuthorizedCodeHandler(provider, helpers, ctx) {
  const {
    findGrantSource,
    consumeGrantSource,
    validateGrant,
  } = helpers;

  presence(ctx, 'pre-authorized_code');

  const dPoP = await dpopValidate(ctx);

  const code = await findGrantSource(
    ctx,
    provider.PreAuthorizedCode,
    ctx.oidc.params['pre-authorized_code'],
    'pre-authorized code',
  );

  const cert = checkMtlsCert(provider, ctx);
  checkDpopRequired(provider, ctx, dPoP);

  if (code.isExpired) {
    throw new InvalidGrant('pre-authorized code is expired');
  }

  if (code.txCode !== undefined) {
    presence(ctx, 'tx_code');
  } else if (ctx.oidc.params.tx_code !== undefined) {
    throw new InvalidRequest('tx_code is not expected for this pre-authorized code');
  }

  await consumeGrantSource(ctx, code, 'pre-authorized code');

  if (
    code.txCode !== undefined
    && (
      typeof ctx.oidc.params.tx_code !== 'string'
      || !constantEquals(code.txCode, ctx.oidc.params.tx_code, 1000)
    )
  ) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('invalid tx_code provided');
  }

  const grant = await validateGrant(ctx, code.grantId);

  ctx.oidc.entity('PreAuthorizedCode', code);
  ctx.oidc.entity('Grant', grant);

  await issueTokens(provider, helpers, ctx, code, grant, {
    gty, entityLabel: 'pre-authorized code', cert, dPoP,
  });
};

export const parameters = new Set(['pre-authorized_code', 'tx_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
