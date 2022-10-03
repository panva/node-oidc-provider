const jsesc = require('jsesc');

const pushInlineSha = require('../helpers/script_src_sha');

const statusCodes = new Set([200, 400, 500]);

module.exports = function webMessage(ctx, redirectUri, response) {
  ctx.type = 'html';

  if (!statusCodes.has(ctx.status)) {
    ctx.status = 'error' in response ? 400 : 200;
  }

  ctx.response.remove('X-Frame-Options');
  const csp = ctx.response.get('Content-Security-Policy');
  if (csp.includes('frame-ancestors')) {
    ctx.response.set('Content-Security-Policy', csp.replace(/ ?frame-ancestors [^;]+;/, ''));
  }

  const data = jsesc({
    response,
    redirect_uri: redirectUri,
    web_message_uri: ctx.oidc.params.web_message_uri,
    web_message_target: ctx.oidc.params.web_message_target,
  }, { json: true, isScriptContext: true });

  ctx.body = `<!DOCTYPE html>
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Web Message Response</title>
</head>
<body>
  <script>${pushInlineSha(ctx, `
    (function(win, doc) {
      var data = ${data};

      var response = data.response;
      var redirect_uri = data.redirect_uri;
      var web_message_uri = data.web_message_uri;
      var web_message_target = data.web_message_target;

      var authorization_response = { type: 'authorization_response', response: response };

      var respond = function (target, origin) {
        document.scripts[0].parentElement.removeChild(document.scripts[0]);
        target.postMessage(authorization_response, origin);
        win.close();
      };

      var mainWin = win.opener || win.parent;
      if (web_message_uri && web_message_target) {
        var onRelayResponse = function(event) {
          if (event.origin !== redirect_uri) return;
          if (event.data.type === 'relay_response') {
            win.removeEventListener('message', onRelayResponse);
            messageTargetWindow = event.source.frames[web_message_target];
            if (messageTargetWindow) {
              respond(messageTargetWindow, web_message_uri);
            }
          }
        }
        win.addEventListener('message', onRelayResponse);
        mainWin.postMessage({ type: 'relay_request' }, redirect_uri);
      } else {
        respond(mainWin, redirect_uri);
      }
    })(this, this.document);
  `)}</script>
</body>
</html>`;
};
