module.exports = `<!DOCTYPE html>
<html >
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
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

      button {
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <div class="login-card">
      <h1><%= title %></h1>
      <%- body %>
      <div class="login-help">
        <a href="/interaction/<%= uid %>/abort">[ Cancel ]</a>
        <% if (client.tosUri) { %>
          <a href="<%= client.tosUri %>">[ Terms of Service ]</a>
        <% } %>
        <% if (client.policyUri) { %>
          <a href="<%= client.policyUri %>">[ Privacy Policy ]</a>
        <% } %>
      </div>
    </div>
    <div class="grant-debug">
      <details>
        <summary style="text-align: center;">(Click to expand) DEBUG information</summary>
        <div>
          <strong>uid</strong>: <%= uid %>
        </div>

        <% if (session) { %>
        <div>
          SESSION <br>
         ========= <br>
          <%- session %>
        </div>
        <% } %>

        <div>
          PARAMS <br>
         ======== <br>
          <%- dbg.params %>
        </div>

        <div>
          PROMPT <br>
         ======== <br>
          <%- dbg.prompt %>
        </div>
      </details>
    </div>
  </body>
</html>`;
