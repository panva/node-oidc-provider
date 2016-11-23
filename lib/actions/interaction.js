'use strict';

const compose = require('koa-compose');
const bodyParser = require('../shared/selective_body');
const instance = require('../helpers/weak_cache');
const views = require('../views');

const parseBody = bodyParser('application/x-www-form-urlencoded');

async function parseCookie(ctx, next) {
  const cookie = ctx.cookies.get('_grant');
  ctx.assert(cookie, 400);
  const fads = JSON.parse(cookie);
  ctx.uuid = ctx.params.grant;

  ['interaction', 'params', 'returnTo'].forEach((detail) => {
    Object.defineProperty(ctx, detail, { get() { return fads[detail]; } });
  });

  await next();
}

module.exports = function devInteractions(provider) {
  /* eslint-disable no-console, no-multi-str */
  console.info('NOTICE: a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');
  /* eslint-enable */
  const router = instance(provider).router;

  return {
    get: compose([
      parseCookie,
      async function interactionRender(ctx, next) {
        const client = await provider.Client.find(ctx.params.client_id);
        ctx.assert(client, 400);

        const action = router.url('interaction', { grant: ctx.uuid });
        const view = (() => {
          switch (ctx.interaction.reason) {
            case 'consent_prompt':
            case 'client_not_authorized':
              return 'interaction';
            default:
              return 'login';
          }
        })();
        const locals = {
          action,
          client,
          returnTo: ctx.returnTo,
          params: ctx.params,
        };
        locals.body = views[view](locals);

        ctx.type = 'html';
        ctx.body = views.layout(locals);

        await next();
      },
    ]),
    post: compose([
      parseBody,
      parseCookie,
      async function interactionSubmit(ctx, next) {
        switch (ctx.request.body.view) { // eslint-disable-line default-case
          case 'login':
            provider.resume(ctx, ctx.uuid, {
              login: {
                account: ctx.request.body.login,
                acr: '1',
                remember: !!ctx.request.body.remember,
                ts: Math.floor(Date.now() / 1000),
              },
              consent: {},
            });
            break;
          case 'interaction':
            provider.resume(ctx, ctx.uuid, { consent: {} });
            break;
        }

        await next();
      },
    ]),
  };
};
