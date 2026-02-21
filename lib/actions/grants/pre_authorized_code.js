import {
  InvalidGrant, InvalidRequest,
} from '../../helpers/errors.js';
import presence from '../../helpers/validate_presence.js';
import instance from '../../helpers/weak_cache.js';
import revoke from '../../helpers/revoke.js';
import dpopValidate from '../../helpers/validate_dpop.js';
import constantEquals from '../../helpers/constant_equals.js';
import {
  checkMtlsCert,
  checkDpopRequired,
  validateGrant,
  validateAccount,
  checkAccountMismatch,
  createAccessToken,
  applyMtlsBinding,
  applyDpopBinding,
  resolveAndApplyResource,
  createRefreshToken,
  buildTokenResponse,
} from '../../helpers/grant_common.js';

export const gty = 'pre_authorized_code';

export const handler = async function preAuthorizedCodeHandler(ctx) {
  presence(ctx, 'pre-authorized_code');

  if (ctx.oidc.params.authorization_details) {
    throw new InvalidRequest('authorization_details is unsupported for this grant_type');
  }

  const {
    findAccount,
    issueRefreshToken,
    features: {
      userinfo,
      mTLS: { getCertificate },
      dPoP: { allowReplay },
      resourceIndicators,
    },
  } = instance(ctx.oidc.provider).configuration;

  const dPoP = await dpopValidate(ctx);

  const code = await ctx.oidc.provider.PreAuthorizedCode.find(ctx.oidc.params['pre-authorized_code'], {
    ignoreExpiration: true,
  });

  if (!code) {
    throw new InvalidGrant('pre-authorized code not found');
  }

  if (code.clientId !== ctx.oidc.client.clientId) {
    throw new InvalidGrant('client mismatch');
  }

  const cert = checkMtlsCert(ctx, getCertificate);
  checkDpopRequired(ctx, dPoP);

  if (code.isExpired) {
    throw new InvalidGrant('pre-authorized code is expired');
  }

  if (code.txCode !== undefined) {
    presence(ctx, 'tx_code');
  } else if (ctx.oidc.params.tx_code !== undefined) {
    throw new InvalidRequest('tx_code is not expected for this pre-authorized code');
  }

  if (code.consumed) {
    await revoke(ctx, code.grantId);
    throw new InvalidGrant('pre-authorized code already consumed');
  }

  await code.consume();

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

  const account = await validateAccount(ctx, findAccount, code, 'pre-authorized code');
  checkAccountMismatch(code, grant);

  ctx.oidc.entity('Account', account);

  const { RefreshToken } = ctx.oidc.provider;

  const at = createAccessToken(
    ctx,
    ctx.oidc.provider.AccessToken,
    { ...code, accountId: account.accountId },
    gty,
  );
  applyMtlsBinding(at, cert);
  await applyDpopBinding(ctx, dPoP, at, allowReplay);

  await resolveAndApplyResource(ctx, code, at, grant, { userinfo, resourceIndicators });

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save();

  const refreshToken = await createRefreshToken(ctx, code, at, gty, {
    issueRefreshToken, RefreshToken,
  });

  ctx.body = buildTokenResponse(at, accessToken, {
    refreshToken, source: code, rar: at.rar,
  });
};

export const parameters = new Set(['pre-authorized_code', 'tx_code']);

export const grantType = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
