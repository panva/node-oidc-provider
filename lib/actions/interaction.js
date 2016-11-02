'use strict';

const compose = require('koa-compose');
const bodyParser = require('../shared/selective_body');
const instance = require('../helpers/weak_cache');

const parseBody = bodyParser('application/x-www-form-urlencoded');

function* parseCookie(next) {
  const cookie = this.cookies.get('_grant');
  this.assert(cookie, 400);
  const fads = JSON.parse(cookie);
  this.uuid = this.params.grant;

  ['interaction', 'params', 'returnTo'].forEach((detail) => {
    Object.defineProperty(this, detail, { get() { return fads[detail]; } });
  });

  yield next;
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
      function* interactionRender() {
        const client = yield provider.Client.find(this.params.client_id);
        this.assert(client, 400);

        const action = router.url('interaction', { grant: this.uuid });
        const view = (() => {
          switch (this.interaction.reason) {
            case 'consent_prompt':
            case 'client_not_authorized':
              return 'interaction';
            default:
              return 'login';
          }
        })();

        yield this.render(view, {
          action,
          client,
          returnTo: this.returnTo,
          params: this.params,
        });
      },
    ]),
    post: compose([
      parseBody,
      parseCookie,
      function* interactionSubmit(next) {
        switch (this.request.body.view) { // eslint-disable-line default-case
          case 'login':
            provider.resume(this, this.uuid, {
              login: {
                account: this.request.body.login,
                acr: '1',
                remember: !!this.request.body.remember,
                ts: Math.floor(Date.now() / 1000),
              },
              consent: {},
            });
            break;
          case 'interaction':
            provider.resume(this, this.uuid, { consent: {} });
            break;
        }

        yield next;
      },
    ]),
  };
};
