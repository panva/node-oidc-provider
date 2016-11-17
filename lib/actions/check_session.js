'use strict';

module.exports = function checkSessionAction() {
  return async function checkSessionIframe(ctx, next) {
    const debug = ctx.query.debug !== undefined;
    ctx.type = 'html';
    ctx.body = `<!DOCTYPE html>
  <html>
  <head lang="en">
    <meta charset="UTF-8">
    <title>Session Management - OP iframe</title>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jsSHA/2.2.0/sha256.js" integrity="sha256-cZOjfJHUnIR4AN0bIASJHvhhJudsombORNNWzHKVoXY=" crossorigin="anonymous"></script>
  </head>
  <body>

  <script type="application/javascript">
    var debug = ${debug};
    function receiveMessage(e) {
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
      var cookie = readCookie('_state.' + clientId);
      if (debug && console) console.log('session state cookie: ' + cookie);
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

  </body>
  </html>`;
    await next();
  };
};
