export const source = `<form autocomplete="off" action="<%= it.submitUrl %>" method="post">
  <input type="hidden" name="prompt" value="login"/>
  <input required type="text" name="login" placeholder="Enter any login" <% if (!it.params.login_hint) { %>autofocus="on"<% } else { %> value="<%= it.params.login_hint %>" <% } %>>
  <input required type="password" name="password" placeholder="and password" <% if (it.params.login_hint) { %>autofocus="on"<% } %>>

  <button type="submit" class="login login-submit">Sign-in</button>
</form>`;

/* eslint-disable */
export default function login(it, options) {
  let include = (template, data) => this.render(template, data, options);
  let includeAsync = (template, data) => this.renderAsync(template, data, options);

  let __eta = { res: "", e: this.config.escapeFunction, f: this.config.filterFunction };

  function layout(path, data) {
    __eta.layout = path;
    __eta.layoutData = data;
  }

  __eta.res += '<form autocomplete="off" action="';
  __eta.res += __eta.e(it.submitUrl);
  __eta.res +=
    '" method="post">\n  <input type="hidden" name="prompt" value="login"/>\n  <input required type="text" name="login" placeholder="Enter any login" ';
  if (!it.params.login_hint) {
    __eta.res += 'autofocus="on"';
  } else {
    __eta.res += ' value="';
    __eta.res += __eta.e(it.params.login_hint);
    __eta.res += '" ';
  }
  __eta.res += '>\n  <input required type="password" name="password" placeholder="and password" ';
  if (it.params.login_hint) {
    __eta.res += 'autofocus="on"';
  }
  __eta.res += '>\n\n  <button type="submit" class="login login-submit">Sign-in</button>\n</form>';

  if (__eta.layout) {
    __eta.res = include(__eta.layout, { ...it, body: __eta.res, ...__eta.layoutData });
  }

  return __eta.res;
}
