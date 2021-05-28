const url = require('url');

const upperFirst = require('../../helpers/_/upper_first');
const camelCase = require('../../helpers/_/camel_case');
const ssHandler = require('../../helpers/samesite_handler');
const errors = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');

/* eslint-disable no-restricted-syntax, no-await-in-loop */

module.exports = async function interactions(resumeRouteName, ctx, next) {
  const { oidc } = ctx;
  let failedCheck;
  let prompt;

  const { policy, url: interactionUrl } = instance(oidc.provider).configuration('interactions');

  for (const { name, checks, details: promptDetails } of policy) {
    let results = (await Promise.all([...checks].map(async ({
      reason, description, error, details, check,
    }) => {
      if (await check(ctx)) {
        return {
          [reason]: { error, description, details: await details(ctx) },
        };
      }

      return undefined;
    }))).filter(Boolean);

    if (results.length) {
      results = Object.assign({}, ...results);
      prompt = {
        name,
        reasons: Object.keys(results),
        details: Object.assign(
          {},
          await promptDetails(ctx),
          ...Object.values(results).map((r) => r.details),
        ),
      };

      const [[, { error, description }]] = Object.entries(results);
      failedCheck = {
        error: error || 'interaction_required',
        error_description: description || 'interaction is required from the end-user',
      };
      break;
    }
  }

  // no interaction requested
  if (!prompt) {
    // check there's an accountId to continue
    if (!oidc.session.accountId) {
      throw new errors.AccessDenied(undefined, 'authorization request resolved without requesting interactions but no account id was resolved');
    }

    // check there's something granted to continue
    // if only claims parameter is used then it must be combined with openid scope anyway
    // when no scope parameter was provided and none is injected by the AS policy access is
    // denied rather then issuing a code/token without scopes
    if (
      !oidc.grant.getOIDCScopeFiltered(oidc.requestParamOIDCScopes)
      && Object.keys(ctx.oidc.resourceServers)
        .every(
          (resource) => !oidc.grant.getResourceScopeFiltered(resource, oidc.requestParamScopes),
        )
    ) {
      throw new errors.AccessDenied(undefined, 'authorization request resolved without requesting interactions but no scope was granted');
    }

    oidc.provider.emit('authorization.accepted', ctx);
    await next();
    return;
  }

  // if interaction needed but prompt=none => throw;
  try {
    if (oidc.promptPending('none')) {
      const className = upperFirst(camelCase(failedCheck.error));
      if (errors[className]) {
        throw new errors[className](failedCheck.error_description);
      }
      throw new errors.CustomOIDCProviderError(failedCheck.error, failedCheck.error_description);
    }
  } catch (err) {
    const code = /^(code|device)_/.test(oidc.route) ? 400 : 303;
    err.status = code;
    err.statusCode = code;
    err.expose = true;
    throw err;
  }

  const uid = nanoid();

  const cookieOptions = instance(oidc.provider).configuration('cookies.short');
  const returnTo = oidc.urlFor(resumeRouteName, {
    uid,
  });

  const interactionSession = new oidc.provider.Interaction(uid, {
    returnTo,
    prompt,
    lastSubmission: oidc.result,
    accountId: oidc.session.accountId,
    params: oidc.params.toPlainObject(),
    trusted: oidc.trusted,
    session: oidc.session,
    grant: oidc.grant,
    ...(oidc.deviceCode ? { deviceCode: oidc.deviceCode.jti } : undefined),
  });

  let ttl = instance(ctx.oidc.provider).configuration('ttl.Interaction');

  if (typeof ttl === 'function') {
    ttl = ttl(ctx, interactionSession);
  }

  await interactionSession.save(ttl);
  ctx.oidc.entity('Interaction', interactionSession);

  const destination = await interactionUrl(ctx, interactionSession);

  ssHandler.set(
    ctx.oidc.cookies,
    oidc.provider.cookieName('interaction'),
    uid,
    {
      path: url.parse(destination).pathname,
      ...cookieOptions,
      maxAge: ttl * 1000,
    },
  );

  ssHandler.set(
    ctx.oidc.cookies,
    oidc.provider.cookieName('resume'),
    uid,
    {
      ...cookieOptions,
      path: url.parse(returnTo).pathname,
      domain: undefined,
      httpOnly: true,
      maxAge: ttl * 1000,
    },
  );

  oidc.provider.emit('interaction.started', ctx, prompt);
  ctx.status = 303;
  ctx.redirect(destination);
};
