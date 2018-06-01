const _ = require('lodash');
const { InvalidGrant, InvalidScope } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getRefreshTokenHandler(provider) {
  const { refreshTokenRotation, audiences } = instance(provider).configuration();

  return async function refreshTokenResponse(ctx, next) {
    presence(ctx, ['refresh_token']);

    const {
      RefreshToken, Account, AccessToken, IdToken,
    } = provider;

    let refreshTokenValue = ctx.oidc.params.refresh_token;
    let refreshToken = await RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

    if (!refreshToken) {
      ctx.throw(new InvalidGrant('refresh token not found'));
    }

    if (refreshToken.isExpired) {
      ctx.throw(new InvalidGrant('refresh token is expired'));
    }

    if (refreshToken.clientId !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidGrant('refresh token client mismatch'));
    }

    const refreshTokenScopes = refreshToken.scope.split(' ');

    if (ctx.oidc.params.scope) {
      const missing = _.difference(ctx.oidc.params.scope.split(' '), refreshTokenScopes);

      if (!_.isEmpty(missing)) {
        ctx.throw(new InvalidScope('refresh token missing requested scope', missing.join(' ')));
      }
    }

    ctx.oidc.entity('RefreshToken', refreshToken);

    const account = await Account.findById(ctx, refreshToken.accountId, refreshToken);

    if (!account) {
      ctx.throw(new InvalidGrant('refresh token invalid (referenced account not found)'));
    }
    ctx.oidc.entity('Account', account);

    if (refreshTokenRotation === 'rotateAndConsume') {
      try {
        if (refreshToken.consumed) {
          ctx.throw(new InvalidGrant('refresh token already used'));
        }

        await refreshToken.consume();
        ctx.oidc.entity('RotatedRefreshToken', refreshToken);

        refreshToken = new RefreshToken({
          accountId: refreshToken.accountId,
          acr: refreshToken.acr,
          amr: refreshToken.amr,
          authTime: refreshToken.authTime,
          claims: refreshToken.claims,
          clientId: refreshToken.clientId,
          grantId: refreshToken.grantId,
          nonce: refreshToken.nonce,
          scope: ctx.oidc.params.scope || refreshToken.scope,
          sid: refreshToken.sid,
        });

        refreshTokenValue = await refreshToken.save();
        ctx.oidc.entity('RefreshToken', refreshToken);
      } catch (err) {
        await refreshToken.destroy();
        throw err;
      }
    }

    const scope = ctx.oidc.params.scope || refreshToken.scope;
    const at = new AccessToken({
      scope,
      accountId: account.accountId,
      claims: refreshToken.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: refreshToken.grantId,
      sid: refreshToken.sid,
    });

    at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token', scope));

    const accessToken = await at.save();
    ctx.oidc.entity('AccessToken', at);
    const { expiresIn } = AccessToken;

    const token = new IdToken(Object.assign({}, await account.claims('id_token', at.scope), {
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), ctx.oidc.client.sectorIdentifier);

    token.scope = refreshToken.scope;
    token.mask = _.get(refreshToken.claims, 'id_token', {});

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', refreshToken.sid);

    const idToken = await token.sign(ctx.oidc.client, {
      audiences: await audiences(ctx, refreshToken.accountId, refreshToken, 'id_token', 'scope'),
    });

    ctx.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshTokenValue,
      scope: at.scope,
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = ['refresh_token', 'scope'];
