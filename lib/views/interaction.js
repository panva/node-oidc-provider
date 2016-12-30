module.exports = `<% title = 'Authorize' %>
<form autocomplete="off" action="<%- action %>" method="post">
  <input type="hidden" name="view" value="interaction"/>
  <button autofocus type="submit" name="submit" class="login login-submit">Continue</button>
</form>`;
