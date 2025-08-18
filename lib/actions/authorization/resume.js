import upperFirst from "../../helpers/_/upper_first.js";
import camelCase from "../../helpers/_/camel_case.js";
import nanoid from "../../helpers/nanoid.js";
import * as errors from "../../helpers/errors.js";
import instance from "../../helpers/weak_cache.js";
import Params from "../../helpers/params.js";
import formPost from "../../response_modes/form_post.js";
import epochTime from "../../helpers/epoch_time.js";

function getInteractionIdFromCookie(ctx) {
 const cookieOptions = instance(ctx.oidc.provider).configuration.cookies.short;
 return ctx.cookies.get(ctx.oidc.provider.cookieName("resume"), cookieOptions);
}

function getInteractionIdFromPath(ctx) {
  // Extract the last part of the pathname, which is the interaction id, e.g. /auth/:interactionId
  // eslint-disable-next-line no-useless-escape
  const interactionIdMatches = ctx.req.url.match(/\/([^\/]+)$/);

  const interactionId = interactionIdMatches[1];
  if (!interactionId) {
    throw new errors.SessionNotFound("No interactionID in path");
  }
  return interactionId;
}

function getInteractionId(ctx) {
  const enableCookielessFallback = instance(ctx.oidc.provider).configuration.cookies.enableCookielessFallback === true;
  const interactionIdFromCookie = getInteractionIdFromCookie(ctx);
  if (!interactionIdFromCookie && !enableCookielessFallback) {
    throw new errors.SessionNotFound('authorization request has expired');
  }
  // We support looking up sessions without a cookie. Look for the interaction ID on the path.
  return interactionIdFromCookie || getInteractionIdFromPath(ctx);
}

export default async function resumeAction(allowList, resumeRouteName, ctx, next) {
  const interactionId = getInteractionId(ctx);
  const interactionSession = await ctx.oidc.provider.Interaction.find(interactionId);
  if (!interactionSession) {
    throw new errors.SessionNotFound("interaction session not found");
  }
  ctx.oidc.entity("Interaction", interactionSession);

  const enableCookielessFallback = instance(ctx.oidc.provider).configuration.cookies.enableCookielessFallback === true;

  // If cookies are enabled, the cookie maxAge will serve to enforce the session TTL.
  // Otherwise, check the interaction's expiry:
  if (enableCookielessFallback && interactionSession.exp && interactionSession.exp < epochTime()) {
    throw new errors.SessionNotFound('interaction has expired');
  }

  if (!enableCookielessFallback && interactionId !== interactionSession.uid) {
    throw new errors.SessionNotFound('authorization session and cookie identifier mismatch');
  }

  const {
    result,
    params: storedParams = {},
    trusted = [],
    session: originSession,
  } = interactionSession;

  const { session } = ctx.oidc;

  if (originSession?.uid && originSession.uid !== session.uid) {
    throw new errors.SessionNotFound("interaction session and authentication session mismatch");
  }

  if (result?.login && session.accountId && session.accountId !== result.login.accountId) {
    if (interactionSession.session?.uid) {
      delete interactionSession.session.uid;
      await interactionSession.save(interactionSession.exp - epochTime());
    }

    session.state = {
      secret: nanoid(),
      clientId: storedParams.client_id,
      postLogoutRedirectUri: ctx.oidc.urlFor(ctx.oidc.route, ctx.params),
    };

    formPost(ctx, ctx.oidc.urlFor("end_session_confirm"), {
      xsrf: session.state.secret,
      logout: "yes",
    });

    return;
  }

  await interactionSession.destroy();

  const params = new (Params(allowList))(storedParams);
  ctx.oidc.params = params;
  ctx.oidc.trusted = trusted;
  ctx.oidc.redirectUriCheckPerformed = true;

  const disableCookies = instance(ctx.oidc.provider).configuration.cookies.doNotSet === true;
  if (!disableCookies) {
    const cookieOptions = instance(ctx.oidc.provider).configuration.cookies.short;
    const clearOpts = {
      ...cookieOptions,
      path: new URL(ctx.oidc.urlFor(resumeRouteName, { uid: interactionSession.uid })).pathname,
    };
    ctx.cookies.set(ctx.oidc.provider.cookieName("resume"), null, clearOpts);
  }

  if (result?.error) {
    const className = upperFirst(camelCase(result.error));
    if (errors[className]) {
      throw new errors[className](result.error_description);
    }
    throw new errors.CustomOIDCProviderError(result.error, result.error_description);
  }

  if (result?.login) {
    const { remember = true, accountId, ts: loginTs, amr, acr } = result.login;

    session.loginAccount({
      accountId,
      loginTs,
      amr,
      acr,
      transient: !remember,
    });
  }

  ctx.oidc.result = result;

  if (!session.new) {
    session.resetIdentifier();
  }

  await next();
}
