const htmlEscape = require('./html_escape');

module.exports = {
  input(action, csrfToken, code) {
    return `<form id="op.deviceInputForm" method="post" action="${action}">
  <input type="hidden" name="xsrf" value="${csrfToken}"/>
  <input onfocus="this.select(); this.onfocus = undefined;" autofocus required ${code ? `value="${htmlEscape(code)}" ` : ''}type="text" name="user_code" placeholder="Enter code"></input>
  </form>`;
  },
  confirm(action, csrfToken, code) {
    return `<form id="op.deviceConfirmForm" method="post" action="${action}">
<input type="hidden" name="xsrf" value="${csrfToken}"/>
<input type="hidden" name="user_code" value="${htmlEscape(code)}"/>
<input type="hidden" name="confirm" value="yes"/>
</form>`;
  },
};
