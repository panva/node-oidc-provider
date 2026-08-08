import omitBy from '../../helpers/_/omit_by.js';
import instance from '../../helpers/weak_cache.js';
import { InvalidRequestUri } from '../../helpers/errors.js';
import processResponseTypes from '../../helpers/process_response_types.js';

/*
 * Based on the authorization request response mode either redirects with parameters in query or
 * fragment or renders auto-submitting form with the response members as hidden fields.
 *
 * If session management is supported stores User-Agent readable cookie with the session stated
 * used by the OP iframe to detect session state changes.
 *
 * @emits: authorization.success
 */
export default async function respond(ctx) {
  let pushedAuthorizationRequest = ctx.oidc.entities.PushedAuthorizationRequest;

  if (!pushedAuthorizationRequest && ctx.oidc.entities.Interaction?.parJti) {
    pushedAuthorizationRequest = await ctx.oidc.provider.PushedAuthorizationRequest.find(
      ctx.oidc.entities.Interaction.parJti,
      { ignoreExpiration: true },
    );
  }

  if (pushedAuthorizationRequest?.consumed) {
    throw new InvalidRequestUri('request_uri is invalid, expired, or was already used');
  }
  await pushedAuthorizationRequest?.consume();

  const out = await processResponseTypes(ctx);

  const { oidc: { params } } = ctx;

  if (params.state !== undefined) {
    out.state = params.state;
  }

  const { responseMode } = ctx.oidc;
  if (!out.id_token && !responseMode.includes('jwt')) {
    out.iss = ctx.oidc.provider.issuer;
  }

  ctx.oidc.provider.emit('authorization.success', ctx, out);

  const handler = instance(ctx.oidc.provider).responseModes.get(responseMode);
  // A key holding undefined serialises differently in every response mode -
  // omitted in web_message, the literal string "undefined" in query, fragment
  // and form_post. Drop them here so that every response mode is handed the
  // same object. See test/web_message/jsesc_parity.test.js.
  await handler(ctx, params.redirect_uri, omitBy(out, (value) => value === undefined));
}
