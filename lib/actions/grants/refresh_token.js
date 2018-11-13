const _ = require('lodash');
const uuidToGrantId = require('debug')('oidc-provider:uuid');

const { InvalidGrant, InvalidScope } = require('../../helpers/errors');
const presence = require('../../helpers/validate_presence');
const instance = require('../../helpers/weak_cache');

const gty = 'refresh_token';

module.exports.handler = function getRefreshTokenHandler(provider) {
  const conf = instance(provider).configuration();

  return async function refreshTokenResponse(ctx, next) {
    presence(ctx, 'refresh_token');
    const {
      refreshTokenRotation, audiences, features: { conformIdTokenClaims },
    } = conf;

    const {
      RefreshToken, Account, AccessToken, IdToken,
    } = provider;

    let refreshTokenValue = ctx.oidc.params.refresh_token;
    let refreshToken = await RefreshToken.find(refreshTokenValue, { ignoreExpiration: true });

    if (!refreshToken) {
      throw new InvalidGrant('refresh token not found');
    }
    uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, refreshToken.grantId);
    ctx.oidc.uuid = refreshToken.grantId;

    if (refreshToken.isExpired) {
      throw new InvalidGrant('refresh token is expired');
    }

    if (refreshToken.clientId !== ctx.oidc.client.clientId) {
      throw new InvalidGrant('refresh token client mismatch');
    }

    const refreshTokenScopes = refreshToken.scope.split(' ');

    if (ctx.oidc.params.scope) {
      const requested = ctx.oidc.params.scope.split(' ');
      const missing = _.difference(requested, refreshTokenScopes);

      if (!requested.includes('openid')) {
        throw new InvalidScope('openid is required scope', requested.join(' '));
      }
      if (!_.isEmpty(missing)) {
        throw new InvalidScope('refresh token missing requested scope', missing.join(' '));
      }
    }

    ctx.oidc.entity('RefreshToken', refreshToken);

    const account = await Account.findById(ctx, refreshToken.accountId, refreshToken);

    if (!account) {
      throw new InvalidGrant('refresh token invalid (referenced account not found)');
    }
    ctx.oidc.entity('Account', account);
    const scope = ctx.oidc.params.scope || refreshToken.scope;

    if (refreshTokenRotation === 'rotateAndConsume') {
      try {
        if (refreshToken.consumed) {
          throw new InvalidGrant('refresh token already used');
        }

        await refreshToken.consume();
        ctx.oidc.entity('RotatedRefreshToken', refreshToken);

        refreshToken = new RefreshToken({
          client: ctx.oidc.client,
          scope: refreshToken.scope,
          accountId: refreshToken.accountId,
          acr: refreshToken.acr,
          amr: refreshToken.amr,
          authTime: refreshToken.authTime,
          claims: refreshToken.claims,
          grantId: refreshToken.grantId,
          nonce: refreshToken.nonce,
          sid: refreshToken.sid,
          resource: refreshToken.resource,
          gty: refreshToken.gty,
        });

        if (!refreshToken.gty.endsWith(gty)) {
          refreshToken.gty = `${refreshToken.gty} ${gty}`;
        }

        refreshTokenValue = await refreshToken.save();
        ctx.oidc.entity('RefreshToken', refreshToken);
      } catch (err) {
        await refreshToken.destroy();
        throw err;
      }
    }

    const at = new AccessToken({
      client: ctx.oidc.client,
      scope,
      accountId: account.accountId,
      claims: refreshToken.claims,
      grantId: refreshToken.grantId,
      sid: refreshToken.sid,
      gty: refreshToken.gty,
    });

    if (ctx.oidc.client.tlsClientCertificateBoundAccessTokens) {
      const cert = ctx.get('x-ssl-client-cert');

      if (!cert) {
        throw new InvalidGrant('MTLS client certificate missing');
      }
      at.setS256Thumbprint(cert);
    }

    if (!at.gty.endsWith(gty)) {
      at.gty = `${at.gty} ${gty}`;
    }

    at.setAudiences(await audiences(ctx, account.accountId, at, 'access_token'));

    const accessToken = await at.save();
    ctx.oidc.entity('AccessToken', at);

    const claims = _.get(refreshToken, 'claims.id_token', {});
    const rejected = _.get(refreshToken, 'claims.rejected', []);
    const token = new IdToken(Object.assign({}, await account.claims('id_token', scope, claims, rejected), {
      acr: refreshToken.acr,
      amr: refreshToken.amr,
      auth_time: refreshToken.authTime,
    }), ctx.oidc.client);

    if (conformIdTokenClaims) {
      token.scope = 'openid';
    } else {
      token.scope = scope;
    }
    token.mask = claims;
    token.rejected = rejected;

    token.set('nonce', refreshToken.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', refreshToken.sid);

    const idToken = await token.sign({
      audiences: await audiences(ctx, refreshToken.accountId, token, 'id_token'),
    });

    ctx.body = {
      access_token: accessToken,
      expires_in: at.expiration,
      id_token: idToken,
      refresh_token: refreshTokenValue,
      scope,
      token_type: 'Bearer',
    };

    await next();
  };
};

module.exports.parameters = new Set(['refresh_token', 'scope']);
