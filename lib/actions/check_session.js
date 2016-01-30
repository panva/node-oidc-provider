'use strict';

module.exports = function() {

  return function * checkSessionIframe() {

    this.type = 'html';
    this.body = `<!DOCTYPE html>
  <html>
  <head lang="en">
    <meta charset="UTF-8">
    <title>Session Management - OP iframe</title>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jsSHA/2.0.2/sha256.js">
    </script>
  </head>
  <body>

  <script type="application/javascript">
    function receiveMessage(e) {
      try {
        var message_parts = e.data.split(' ');
        var clientId = message_parts[0];
        var sessionState = message_parts[1];
        console.log('OP recv session state: ' + sessionState);
        var salt = sessionState.split('.')[1];

        var opbs = getOPBrowserState(clientId);
        var shaObj = new jsSHA('SHA-256', 'TEXT');
        shaObj.update(clientId + ' ' + e.origin + ' ' + opbs + ' ' + salt);
        var ss = shaObj.getHash('HEX') + ['.' + salt];
        console.log('OP computed session state: ' + ss);

        var stat;
        if (sessionState === ss) {
          stat = 'unchanged';
        } else {
          stat = 'changed';
        }

        console.log('OP status: ' + stat);

        e.source.postMessage(stat, e.origin);
      } catch (err) {
        e.source.postMessage('error', e.origin);
      }
    }

    function getOPBrowserState(clientId) {
      var cookie = readCookie('_session_states');
      console.log('_session_states cookie: ' + cookie);

      if (cookie !== null) {
        cookie = JSON.parse(cookie)[clientId];
      }

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

  };
};
