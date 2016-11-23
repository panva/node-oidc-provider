module.exports = `<% title = 'Sign-in' %>
<form autocomplete="off" action="<%- action %>" method="post">
  <input type="hidden" name="view" value="login"/>
  <input required type="text" name="login" placeholder="Enter any login" <% if (!params.login_hint) { %>autofocus="on"<% } else { %> value="<%= params.login_hint %>" <% } %>>
  <input required type="password" name="password" placeholder="and password" <% if (params.login_hint) { %>autofocus="on"<% } %>>

  <label><input type="checkbox" name="remember" value="yes" checked="yes">Stay signed in</label>

  <button type="submit" name="submit" class="login login-submit">Sign-in</button>
</form>`;
