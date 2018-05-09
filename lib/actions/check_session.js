const instance = require('../helpers/weak_cache');

module.exports = function checkSessionAction(provider) {
  const removeHeaders = !instance(provider).configuration('features.sessionManagement.keepHeaders');
  const thirdPartyCheckUrl = instance(provider).configuration('cookies.thirdPartyCheckUrl');

  return async function checkSessionIframe(ctx, next) {
    const debug = ctx.query.debug !== undefined;

    if (removeHeaders) {
      ctx.response.remove('X-Frame-Options');
      const csp = ctx.response.get('Content-Security-Policy');
      if (csp.includes('frame-ancestors')) {
        ctx.response.set('Content-Security-Policy', csp.replace(/ ?frame-ancestors [^;]+;/, ''));
      }
    }

    ctx.type = 'html';
    ctx.body = `<!DOCTYPE html>
  <html>
  <head lang="en">
    <meta charset="UTF-8">
    <title>Session Management - OP iframe</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsSHA/2.3.1/sha256.js" integrity="sha256-NyuvLfsvfCfE+ceV6/W19H+qVp3M8c9FzAgj72CW39w=" crossorigin="anonymous"></script>
  </head>
  <body>

  <script type="application/javascript">
    var debug = ${debug};
    var thirdPartyCookies = true;

    function receiveMessage(e) {
      if (e.data === 'MM:3PCunsupported') {
        thirdPartyCookies = false;
        return;
      } else if (e.data === 'MM:3PCsupported') {
        return;
      }
      try {
        var message_parts = e.data.split(' ');
        var clientId = message_parts[0];
        var actual = message_parts[1];
        if (debug && console) console.log('OP recv session state: ' + actual);
        var salt = actual.split('.')[1];

        var opbs = getOPBrowserState(clientId);
        var shaObj = new jsSHA('SHA-256', 'TEXT');
        shaObj.update(clientId + ' ' + e.origin + ' ' + opbs + ' ' + salt);
        var expected = shaObj.getHash('HEX') + ['.' + salt];
        if (debug && console) console.log('OP computed session state: ' + expected);

        var stat;
        if (actual === expected) {
          stat = 'unchanged';
        } else {
          stat = 'changed';
        }

        if (debug && console) console.log('OP status: ' + stat);

        e.source.postMessage(stat, e.origin);
      } catch (err) {
        e.source.postMessage('error', e.origin);
      }
    }

    function getOPBrowserState(clientId) {
      var cookie = readCookie('${provider.cookieName('state')}.' + clientId);
      if (debug && console) console.log('session state cookie: ' + cookie);
      if (!thirdPartyCookies && !cookie) throw new Error('third party cookies are most likely blocked');
      return cookie;
    }

    function readCookie(name) {
      var nameEQ = name + "=";
      var ca = document.cookie.split(';');
      for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
      }
      return null;
    }

    window.addEventListener('message', receiveMessage, false);
  </script>
  <iframe src="${thirdPartyCheckUrl}" style="display:none" />

  </body>
  </html>`;
    await next();
  };
};
