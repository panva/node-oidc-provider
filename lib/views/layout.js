export const source = `<!DOCTYPE html>
<html >
  <head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Sign-in</title>
    <style>
      @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);

      body {
        font-family: 'Roboto', sans-serif;
        margin-top: 25px;
        margin-bottom: 25px;
      }

      .login-card {
        padding: 40px;
        padding-top: 0px;
        padding-bottom: 10px;
        width: 274px;
        background-color: #F7F7F7;
        margin: 0 auto 10px;
        border-radius: 2px;
        box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
        overflow: hidden;
      }

      .login-card + .login-card {
        padding-top: 10px;
      }

      .login-card h1 {
        font-weight: 100;
        text-align: center;
        font-size: 2.3em;
      }

      .login-card [type=submit] {
        width: 100%;
        display: block;
        margin-bottom: 10px;
        position: relative;
      }

      .login-card input[type=text], input[type=email], input[type=password] {
        height: 44px;
        font-size: 16px;
        width: 100%;
        margin-bottom: 10px;
        -webkit-appearance: none;
        background: #fff;
        border: 1px solid #d9d9d9;
        border-top: 1px solid #c0c0c0;
        padding: 0 8px;
        box-sizing: border-box;
        -moz-box-sizing: border-box;
      }

      .login {
        text-align: center;
        font-size: 14px;
        font-family: 'Arial', sans-serif;
        font-weight: 700;
        height: 36px;
        padding: 0 8px;
      }

      .login-submit {
        border: 0px;
        color: #fff;
        text-shadow: 0 1px rgba(0,0,0,0.1);
        background-color: #4d90fe;
      }

      .login-card a {
        text-decoration: none;
        color: #666;
        font-weight: 400;
        text-align: center;
        display: inline-block;
        opacity: 0.6;
      }

      .login-help {
        width: 100%;
        text-align: center;
        font-size: 12px;
      }

      .login-client-image img {
        margin-bottom: 20px;
        display: block;
        margin-left: auto;
        margin-right: auto;
        width: 20%;
      }

      .login-card input[type=checkbox] {
        margin-bottom: 10px;
      }

      .login-card label {
        color: #999;
      }

      .grant-debug {
        text-align: center;
        font-family: Fixed, monospace;
        width: 100%;
        font-size: 12px;
        color: #999;
      }

      .grant-debug div {
        padding-top: 10px;
      }

      ul {
        font-weight: 100;
        padding-left: 1em;
        list-style-type: circle;
      }

      li + ul, ul + li, li + li {
        padding-top: 0.3em;
      }

      li > pre {
        font-size: 12px;
        font-family: Fixed, monospace;
        margin: 0px;
      }

      button {
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <div class="login-card">
      <h1><%= it.title %></h1>
      <%~ it.body %>
      <div class="login-help">
        <a href="<%= it.abortUrl %>">[ Cancel ]</a>
        <% if (it.client.tosUri) { %>
          <a href="<%= it.client.tosUri %>">[ Terms of Service ]</a>
        <% } %>
        <% if (it.client.policyUri) { %>
          <a href="<%= it.client.policyUri %>">[ Privacy Policy ]</a>
        <% } %>
      </div>
    </div>
    <div class="grant-debug">
      <details>
        <summary style="text-align: center;">(Click to expand) DEBUG information</summary>
        <div>
          <strong>uid</strong>: <%= it.uid %>
        </div>

        <% if (it.session) { %>
        <div>
          SESSION <br>
         ========= <br>
          <%~ it.session %>
        </div>
        <% } %>

        <div>
          PARAMS <br>
         ======== <br>
          <%~ it.dbg.params %>
        </div>

        <div>
          PROMPT <br>
         ======== <br>
          <%~ it.dbg.prompt %>
        </div>
      </details>
    </div>
  </body>
</html>`;

/* eslint-disable */
export default function layout(it, options) {
  let include = (template, data) => this.render(template, data, options);
  let includeAsync = (template, data) => this.renderAsync(template, data, options);

  let __eta = { res: "", e: this.config.escapeFunction, f: this.config.filterFunction };

  function layout(path, data) {
    __eta.layout = path;
    __eta.layoutData = data;
  }

  __eta.res +=
    '<!DOCTYPE html>\n<html >\n  <head>\n    <meta http-equiv="X-UA-Compatible" content="IE=edge">\n    <meta charset="utf-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\n    <title>Sign-in</title>\n    <style>\n      @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);\n\n      body {\n        font-family: \'Roboto\', sans-serif;\n        margin-top: 25px;\n        margin-bottom: 25px;\n      }\n\n      .login-card {\n        padding: 40px;\n        padding-top: 0px;\n        padding-bottom: 10px;\n        width: 274px;\n        background-color: #F7F7F7;\n        margin: 0 auto 10px;\n        border-radius: 2px;\n        box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n        overflow: hidden;\n      }\n\n      .login-card + .login-card {\n        padding-top: 10px;\n      }\n\n      .login-card h1 {\n        font-weight: 100;\n        text-align: center;\n        font-size: 2.3em;\n      }\n\n      .login-card [type=submit] {\n        width: 100%;\n        display: block;\n        margin-bottom: 10px;\n        position: relative;\n      }\n\n      .login-card input[type=text], input[type=email], input[type=password] {\n        height: 44px;\n        font-size: 16px;\n        width: 100%;\n        margin-bottom: 10px;\n        -webkit-appearance: none;\n        background: #fff;\n        border: 1px solid #d9d9d9;\n        border-top: 1px solid #c0c0c0;\n        padding: 0 8px;\n        box-sizing: border-box;\n        -moz-box-sizing: border-box;\n      }\n\n      .login {\n        text-align: center;\n        font-size: 14px;\n        font-family: \'Arial\', sans-serif;\n        font-weight: 700;\n        height: 36px;\n        padding: 0 8px;\n      }\n\n      .login-submit {\n        border: 0px;\n        color: #fff;\n        text-shadow: 0 1px rgba(0,0,0,0.1);\n        background-color: #4d90fe;\n      }\n\n      .login-card a {\n        text-decoration: none;\n        color: #666;\n        font-weight: 400;\n        text-align: center;\n        display: inline-block;\n        opacity: 0.6;\n      }\n\n      .login-help {\n        width: 100%;\n        text-align: center;\n        font-size: 12px;\n      }\n\n      .login-client-image img {\n        margin-bottom: 20px;\n        display: block;\n        margin-left: auto;\n        margin-right: auto;\n        width: 20%;\n      }\n\n      .login-card input[type=checkbox] {\n        margin-bottom: 10px;\n      }\n\n      .login-card label {\n        color: #999;\n      }\n\n      .grant-debug {\n        text-align: center;\n        font-family: Fixed, monospace;\n        width: 100%;\n        font-size: 12px;\n        color: #999;\n      }\n\n      .grant-debug div {\n        padding-top: 10px;\n      }\n\n      ul {\n        font-weight: 100;\n        padding-left: 1em;\n        list-style-type: circle;\n      }\n\n      li + ul, ul + li, li + li {\n        padding-top: 0.3em;\n      }\n\n      li > pre {\n        font-size: 12px;\n        font-family: Fixed, monospace;\n        margin: 0px;\n      }\n\n      button {\n        cursor: pointer;\n      }\n    </style>\n  </head>\n  <body>\n    <div class="login-card">\n      <h1>';
  __eta.res += __eta.e(it.title);
  __eta.res += "</h1>\n      ";
  __eta.res += it.body;
  __eta.res += '      <div class="login-help">\n        <a href="';
  __eta.res += __eta.e(it.abortUrl);
  __eta.res += '">[ Cancel ]</a>\n        ';
  if (it.client.tosUri) {
    __eta.res += '          <a href="';
    __eta.res += __eta.e(it.client.tosUri);
    __eta.res += '">[ Terms of Service ]</a>\n        ';
  }
  __eta.res += "        ";
  if (it.client.policyUri) {
    __eta.res += '          <a href="';
    __eta.res += __eta.e(it.client.policyUri);
    __eta.res += '">[ Privacy Policy ]</a>\n        ';
  }
  __eta.res +=
    '      </div>\n    </div>\n    <div class="grant-debug">\n      <details>\n        <summary style="text-align: center;">(Click to expand) DEBUG information</summary>\n        <div>\n          <strong>uid</strong>: ';
  __eta.res += __eta.e(it.uid);
  __eta.res += "        </div>\n\n        ";
  if (it.session) {
    __eta.res += "        <div>\n          SESSION <br>\n         ========= <br>\n          ";
    __eta.res += it.session;
    __eta.res += "        </div>\n        ";
  }
  __eta.res += "\n        <div>\n          PARAMS <br>\n         ======== <br>\n          ";
  __eta.res += it.dbg.params;
  __eta.res +=
    "        </div>\n\n        <div>\n          PROMPT <br>\n         ======== <br>\n          ";
  __eta.res += it.dbg.prompt;
  __eta.res += "        </div>\n      </details>\n    </div>\n  </body>\n</html>";

  if (__eta.layout) {
    __eta.res = include(__eta.layout, { ...it, body: __eta.res, ...__eta.layoutData });
  }

  return __eta.res;
}
