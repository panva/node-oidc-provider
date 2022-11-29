import { InvalidRequest, UnknownUserId } from '../../helpers/errors.js';
import omitBy from '../../helpers/_/omit_by.js';
import instance from '../../helpers/weak_cache.js';

import checkIdTokenHint from './check_id_token_hint.js';

export default async function cibaLoadAccount(ctx, next) {
  const mechanisms = omitBy({
    login_hint_token: ctx.oidc.params.login_hint_token,
    id_token_hint: ctx.oidc.params.id_token_hint,
    login_hint: ctx.oidc.params.login_hint,
  }, (value) => typeof value !== 'string' || !value);

  let mechanism;
  let length;
  let value;

  try {
    ({ 0: [mechanism, value], length } = Object.entries(mechanisms));
  } catch (err) {}

  if (!length) {
    throw new InvalidRequest('missing one of required parameters login_hint_token, id_token_hint, or login_hint');
  } else if (length !== 1) {
    throw new InvalidRequest('only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided');
  }

  const { features: { ciba } } = instance(ctx.oidc.provider).configuration();

  let accountId;
  // eslint-disable-next-line default-case
  switch (mechanism) {
    case 'id_token_hint':
      await checkIdTokenHint(ctx, () => {});
      ({ payload: { sub: accountId } } = ctx.oidc.entities.IdTokenHint);
      break;
    case 'login_hint_token':
      accountId = await ciba.processLoginHintToken(ctx, value);
      break;
    case 'login_hint':
      accountId = await ciba.processLoginHint(ctx, value);
      break;
  }

  if (!accountId) {
    throw new UnknownUserId('could not identify end-user');
  }
  const account = await ctx.oidc.provider.Account.findAccount(ctx, accountId);
  if (!account) {
    throw new UnknownUserId('could not identify end-user');
  }
  ctx.oidc.entity('Account', account);

  await ciba.verifyUserCode(ctx, account, value);

  return next();
}
