'use strict';

const compose = require('koa-compose');
const bodyParser = require('../shared/selective_body');
const instance = require('../helpers/weak_cache');
const views = require('../views');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function devInteractions(provider) {
  /* eslint-disable no-console, no-multi-str */
  console.info('NOTICE: a quick start development-only feature devInteractions is enabled, \
you are expected to disable these interactions and provide your own');
  /* eslint-enable */
  const router = instance(provider).router;

  return {
    get: compose([
      function* interactionRender() {
        const details = provider.interactionDetails(this.req);
        const client = yield provider.Client.find(details.params.client_id);
        this.assert(client, 400);

        const action = router.url('submit', { grant: details.uuid });
        const view = (() => {
          switch (details.interaction.reason) {
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
          returnTo: details.returnTo,
          params: details.params,
        };
        locals.body = views[view](locals);

        this.type = 'html';
        this.body = views.layout(locals);
      },
    ]),
    post: compose([
      parseBody,
      function* interactionSubmit(next) {
        switch (this.oidc.body.view) { // eslint-disable-line default-case
          case 'login':
            provider.interactionFinished(this.req, this.res, {
              login: {
                account: this.oidc.body.login,
                acr: '1',
                remember: !!this.oidc.body.remember,
                ts: Math.floor(Date.now() / 1000),
              },
              consent: {},
            });
            break;
          case 'interaction':
            provider.interactionFinished(this.req, this.res, { consent: {} });
            break;
        }

        yield next;
      },
    ]),
  };
};
