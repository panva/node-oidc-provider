const _ = require('lodash');
const { InvalidGrantError } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

module.exports.handler = function getRefreshTokenHandler(provider) {
  return async function refreshTokenResponse(ctx, next) {
    presence(ctx, ['refresh_token']);

    const {
      RefreshToken, Account, AccessToken, IdToken,
    } = provider;

    let refreshTokenValue = ctx.oidc.params.refresh_token;
    let refreshToken = await RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

    if (!refreshToken) {
      ctx.throw(new InvalidGrantError('refresh token not found'));
    }

    if (refreshToken.isExpired) {
      ctx.throw(new InvalidGrantError('refresh token is expired'));
    }

    if (refreshToken.clientId !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidGrantError('refresh token client mismatch'));
    }

    const refreshTokenScopes = refreshToken.scope.split(' ');

    if (ctx.oidc.params.scope) {
      const missing = _.difference(ctx.oidc.params.scope.split(' '), refreshTokenScopes);

      if (!_.isEmpty(missing)) {
        ctx.throw(400, 'invalid_scope', {
          error_description: 'refresh token missing requested scope',
          scope: missing.join(' '),
        });
      }
    }

    const account = await Account.findById(ctx, refreshToken.accountId, refreshToken);

    if (!account) {
      ctx.throw(new InvalidGrantError('refresh token invalid (referenced account not found)'));
    }

    if (instance(provider).configuration('refreshTokenRotation') === 'rotateAndConsume') {
      try {
        if (refreshToken.consumed) {
          ctx.throw(new InvalidGrantError('refresh token already used'));
        }

        await refreshToken.consume();

        refreshToken = new RefreshToken(Object.assign({}, {
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
        }));

        refreshTokenValue = await refreshToken.save();
      } catch (err) {
        await refreshToken.destroy();
        throw err;
      }
    }

    const at = new AccessToken({
      accountId: account.accountId,
      claims: refreshToken.claims,
      clientId: ctx.oidc.client.clientId,
      grantId: refreshToken.grantId,
      scope: ctx.oidc.params.scope || refreshToken.scope,
      sid: refreshToken.sid,
    });

    const accessToken = await at.save();
    const { expiresIn } = AccessToken;

    const token = new IdToken(Object.assign({}, await Promise.resolve(account.claims()), {
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), ctx.oidc.client.sectorIdentifier);

    token.scope = refreshToken.scope;
    token.mask = _.get(refreshToken.claims, 'id_token', {});

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('rt_hash', refreshTokenValue);
    token.set('sid', refreshToken.sid);

    const idToken = await token.sign(ctx.oidc.client);

    ctx.body = {
      access_token: accessToken,
      expires_in: expiresIn,
      id_token: idToken,
      refresh_token: refreshTokenValue,
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = ['refresh_token', 'scope'];
