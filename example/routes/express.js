const querystring = require('querystring');

const { urlencoded } = require('express');

const Account = require('../support/account');

const body = urlencoded({ extended: false });

module.exports = (app, provider) => {
  const { constructor: { errors: { SessionNotFound } } } = provider;

  app.use((req, res, next) => {
    const orig = res.render;
    // you'll probably want to use a full blown render engine capable of layouts
    res.render = (view, locals) => {
      app.render(view, locals, (err, html) => {
        if (err) throw err;
        orig.call(res, '_layout', {
          ...locals,
          body: html,
        });
      });
    };
    next();
  });

  app.get('/interaction/:grant', async (req, res, next) => {
    try {
      const details = await provider.interactionDetails(req);
      const client = await provider.Client.find(details.params.client_id);

      if (details.interaction.error === 'login_required') {
        return res.render('login', {
          client,
          details,
          title: 'Sign-in',
          params: querystring.stringify(details.params, ',<br/>', ' = ', {
            encodeURIComponent: value => value,
          }),
          interaction: querystring.stringify(details.interaction, ',<br/>', ' = ', {
            encodeURIComponent: value => value,
          }),
        });
      }
      return res.render('interaction', {
        client,
        details,
        title: 'Authorize',
        params: querystring.stringify(details.params, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
        interaction: querystring.stringify(details.interaction, ',<br/>', ' = ', {
          encodeURIComponent: value => value,
        }),
      });
    } catch (err) {
      return next(err);
    }
  });

  app.post('/interaction/:grant/confirm', body, async (req, res, next) => {
    try {
      const result = { consent: {} };
      await provider.interactionFinished(req, res, result);
    } catch (err) {
      next(err);
    }
  });

  app.post('/interaction/:grant/login', body, async (req, res, next) => {
    try {
      const account = await Account.findByLogin(req.body.login);

      const result = {
        login: {
          account: account.accountId,
          acr: 'urn:mace:incommon:iap:bronze',
          amr: ['pwd'],
          remember: !!req.body.remember,
          ts: Math.floor(Date.now() / 1000),
        },
        consent: {},
      };

      await provider.interactionFinished(req, res, result);
    } catch (err) {
      next(err);
    }
  });

  app.use((err, req, res, next) => {
    if (err instanceof SessionNotFound) {
      // handle interaction expired / session not found error
    }
    next(err);
  });
};
