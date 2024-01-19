import difference from '../helpers/_/difference.js';
import setWWWAuthenticate from '../helpers/set_www_authenticate.js';
import bodyParser from '../shared/conditional_body.js';
import rejectDupes from '../shared/reject_dupes.js';
import paramsMiddleware from '../shared/assemble_params.js';
import noCache from '../shared/no_cache.js';
import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import instance from '../helpers/weak_cache.js';
import filterClaims from '../helpers/filter_claims.js';
import dpopValidate from '../helpers/validate_dpop.js';
import epochTime from '../helpers/epoch_time.js';
import {
  InvalidToken, InsufficientScope, InvalidDpopProof, UseDpopNonce,
} from '../helpers/errors.js';

const PARAM_LIST = new Set([
  'scope',
  'access_token',
]);

const parseBody = bodyParser.bind(undefined, 'application/x-www-form-urlencoded');

export default [
  noCache,

  async function setWWWAuthenticateHeader(ctx, next) {
    try {
      await next();
    } catch (err) {
      if (err.expose) {
        let scheme;

        if (/dpop/i.test(err.error_description) || (ctx.oidc.accessToken?.jkt)) {
          scheme = 'DPoP';
        } else {
          scheme = 'Bearer';
        }

        if (err instanceof InvalidDpopProof || err instanceof UseDpopNonce) {
          // eslint-disable-next-line no-multi-assign
          err.status = err.statusCode = 401;
        }

        setWWWAuthenticate(ctx, scheme, {
          realm: ctx.oidc.issuer,
          ...(err.error_description !== 'no access token provided' ? {
            error: err.message,
            error_description: err.error_description,
            scope: err.scope,
          } : undefined),
          ...(scheme === 'DPoP' ? {
            algs: instance(ctx.oidc.provider).configuration('dPoPSigningAlgValues').join(' '),
          } : undefined),
        });
      }
      throw err;
    }
  },

  parseBody,
  paramsMiddleware.bind(undefined, PARAM_LIST),
  rejectDupes.bind(undefined, {}),

  async function validateAccessToken(ctx, next) {
    const accessTokenValue = ctx.oidc.getAccessToken({ acceptDPoP: true });

    const dPoP = await dpopValidate(ctx, accessTokenValue);

    console.log('gio: accessTokenValue in userinfo:', accessTokenValue);
    const accessToken = await ctx.oidc.provider.AccessToken.find(accessTokenValue);

    ctx.assert(accessToken, new InvalidToken('access token not found'));

    ctx.oidc.entity('AccessToken', accessToken);

    const { scopes } = accessToken;
    if (!scopes.size || !scopes.has('openid')) {
      throw new InsufficientScope('access token missing openid scope', 'openid');
    }

    if (accessToken['x5t#S256']) {
      const getCertificate = instance(ctx.oidc.provider).configuration('features.mTLS.getCertificate');
      const cert = getCertificate(ctx);
      if (!cert || accessToken['x5t#S256'] !== certificateThumbprint(cert)) {
        throw new InvalidToken('failed x5t#S256 verification');
      }
    }

    if (dPoP) {
      const unique = await ctx.oidc.provider.ReplayDetection.unique(
        accessToken.clientId,
        dPoP.jti,
        epochTime() + 300,
      );

      ctx.assert(unique, new InvalidToken('DPoP proof JWT Replay detected'));
    }

    if (accessToken.jkt && (!dPoP || accessToken.jkt !== dPoP.thumbprint)) {
      throw new InvalidToken('failed jkt verification');
    }

    await next();
  },

  function validateAudience(ctx, next) {
    const { oidc: { entities: { AccessToken: accessToken } } } = ctx;

    if (accessToken.aud !== undefined) {
      throw new InvalidToken('token audience prevents accessing the userinfo endpoint');
    }

    return next();
  },

  async function validateScope(ctx, next) {
    if (ctx.oidc.params.scope) {
      const missing = difference(ctx.oidc.params.scope.split(' '), [...ctx.oidc.accessToken.scopes]);

      if (missing.length !== 0) {
        throw new InsufficientScope('access token missing requested scope', missing.join(' '));
      }
    }
    await next();
  },

  async function loadClient(ctx, next) {
    const client = await ctx.oidc.provider.Client.find(ctx.oidc.accessToken.clientId);
    ctx.assert(client, new InvalidToken('associated client not found'));

    ctx.oidc.entity('Client', client);

    await next();
  },

  async function loadAccount(ctx, next) {
    const account = await ctx.oidc.provider.Account.findAccount(
      ctx,
      ctx.oidc.accessToken.accountId,
      ctx.oidc.accessToken,
    );

    ctx.assert(account, new InvalidToken('associated account not found'));
    ctx.oidc.entity('Account', account);

    await next();
  },

  async function loadGrant(ctx, next) {
    const grant = await ctx.oidc.provider.Grant.find(ctx.oidc.accessToken.grantId, {
      ignoreExpiration: true,
    });

    if (!grant) {
      throw new InvalidToken('grant not found');
    }

    if (grant.isExpired) {
      throw new InvalidToken('grant is expired');
    }

    if (grant.clientId !== ctx.oidc.accessToken.clientId) {
      throw new InvalidToken('clientId mismatch');
    }

    if (grant.accountId !== ctx.oidc.accessToken.accountId) {
      throw new InvalidToken('accountId mismatch');
    }

    ctx.oidc.entity('Grant', grant);

    await next();
  },

  async function respond(ctx, next) {
    const claims = filterClaims(ctx.oidc.accessToken.claims, 'userinfo', ctx.oidc.grant);
    const rejected = ctx.oidc.grant.getRejectedOIDCClaims();
    const scope = ctx.oidc.grant.getOIDCScopeFiltered(new Set((ctx.oidc.params.scope || ctx.oidc.accessToken.scope).split(' ')));
    const { client } = ctx.oidc;

    if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
      const token = new ctx.oidc.provider.IdToken(
        await ctx.oidc.account.claims('userinfo', scope, claims, rejected),
        { ctx },
      );

      token.scope = scope;
      token.mask = claims;
      token.rejected = rejected;

      ctx.body = await token.issue({
        expiresAt: ctx.oidc.accessToken.exp,
        use: 'userinfo',
      });
      ctx.type = 'application/jwt; charset=utf-8';
    } else {
      const mask = new ctx.oidc.provider.Claims(
        await ctx.oidc.account.claims('userinfo', scope, claims, rejected),
        { ctx },
      );

      mask.scope(scope);
      mask.mask(claims);
      mask.rejected(rejected);

      ctx.body = await mask.result();
    }

    await next();
  },
];
