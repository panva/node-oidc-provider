export const source = `<div class="login-client-image">
  <% if (it.client.logoUri) { %><img src="<%= it.client.logoUri %>"><% } %>
</div>

<ul>
<% if ([it.details.missingOIDCScope, it.details.missingOIDCClaims, it.details.missingResourceScopes, it.details.rar].filter(Boolean).length === 0) { %>
  <li>the client is asking you to confirm previously given authorization</li>
<% } %>

<% let missingOIDCScope = new Set(it.details.missingOIDCScope); missingOIDCScope.delete('openid'); missingOIDCScope.delete('offline_access') %>
<% if (missingOIDCScope.size) { %>
  <li>scopes:</li>
  <ul>
    <% missingOIDCScope.forEach((scope) => { %>
      <li><%= scope %></li>
    <% }) %>
  </ul>
<% } %>

<% let missingOIDCClaims = new Set(it.details.missingOIDCClaims); ['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].forEach(Set.prototype.delete.bind(missingOIDCClaims)) %>
<% if (missingOIDCClaims.size) { %>
  <li>claims:</li>
  <ul>
    <% missingOIDCClaims.forEach((claim) => { %>
      <li><%= claim %></li>
    <% }) %>
  </ul>
<% } %>

<% let missingResourceScopes = it.details.missingResourceScopes %>
<% if (missingResourceScopes) { %>
  <% for (const [indicator, scopes] of Object.entries(it.details.missingResourceScopes)) { %>
    <li><%= indicator %>:</li>
    <ul>
      <% scopes.forEach((scope) => { %>
        <li><%= scope %></li>
      <% }) %>
    </ul>
  <% } %>
<% } %>

<% let rar = it.details.rar %>
<% if (rar) { %>
  <li>authorization_details:</li>
  <ul>
    <% for (const { type, ...detail } of it.details.rar) { %>
      <li><pre><%= JSON.stringify({ type, ...detail }, null, 4) %></pre></li>
    <% } %>
  </ul>
<% } %>

<% if (it.params.scope?.includes('offline_access')) { %>
  <li>
  the client is asking to have offline access to this authorization
    <% if ((!it.details.missingOIDCScope) || !it.details.missingOIDCScope.includes('offline_access')) { %>
      (which you've previously granted)
    <% } %>
  </li>
<% } %>

</ul>

<form autocomplete="off" action="<%= it.submitUrl %>" method="post">
  <input type="hidden" name="prompt" value="consent"/>
  <button autofocus type="submit" class="login login-submit">Continue</button>
</form>
`;

/* eslint-disable */
export default function interaction(it, options) {
  let include = (template, data) => this.render(template, data, options);
  let includeAsync = (template, data) => this.renderAsync(template, data, options);

  let __eta = { res: "", e: this.config.escapeFunction, f: this.config.filterFunction };

  function layout(path, data) {
    __eta.layout = path;
    __eta.layoutData = data;
  }

  __eta.res += '<div class="login-client-image">\n  ';
  if (it.client.logoUri) {
    __eta.res += '<img src="';
    __eta.res += __eta.e(it.client.logoUri);
    __eta.res += '">';
  }
  __eta.res += "</div>\n\n<ul>\n";
  if (
    [
      it.details.missingOIDCScope,
      it.details.missingOIDCClaims,
      it.details.missingResourceScopes,
      it.details.rar,
    ].filter(Boolean).length === 0
  ) {
    __eta.res += "  <li>the client is asking you to confirm previously given authorization</li>\n";
  }
  __eta.res += "\n";
  let missingOIDCScope = new Set(it.details.missingOIDCScope);
  missingOIDCScope.delete("openid");
  missingOIDCScope.delete("offline_access");
  if (missingOIDCScope.size) {
    __eta.res += "  <li>scopes:</li>\n  <ul>\n    ";
    missingOIDCScope.forEach((scope) => {
      __eta.res += "      <li>";
      __eta.res += __eta.e(scope);
      __eta.res += "</li>\n    ";
    });
    __eta.res += "  </ul>\n";
  }
  __eta.res += "\n";
  let missingOIDCClaims = new Set(it.details.missingOIDCClaims);
  ["sub", "sid", "auth_time", "acr", "amr", "iss"].forEach(
    Set.prototype.delete.bind(missingOIDCClaims)
  );
  if (missingOIDCClaims.size) {
    __eta.res += "  <li>claims:</li>\n  <ul>\n    ";
    missingOIDCClaims.forEach((claim) => {
      __eta.res += "      <li>";
      __eta.res += __eta.e(claim);
      __eta.res += "</li>\n    ";
    });
    __eta.res += "  </ul>\n";
  }
  __eta.res += "\n";
  let missingResourceScopes = it.details.missingResourceScopes;
  if (missingResourceScopes) {
    __eta.res += "  ";
    for (const [indicator, scopes] of Object.entries(it.details.missingResourceScopes)) {
      __eta.res += "    <li>";
      __eta.res += __eta.e(indicator);
      __eta.res += ":</li>\n    <ul>\n      ";
      scopes.forEach((scope) => {
        __eta.res += "        <li>";
        __eta.res += __eta.e(scope);
        __eta.res += "</li>\n      ";
      });
      __eta.res += "    </ul>\n  ";
    }
  }
  __eta.res += "\n";
  let rar = it.details.rar;
  if (rar) {
    __eta.res += "  <li>authorization_details:</li>\n  <ul>\n    ";
    for (const { type, ...detail } of it.details.rar) {
      __eta.res += "      <li><pre>";
      __eta.res += __eta.e(JSON.stringify({ type, ...detail }, null, 4));
      __eta.res += "</pre></li>\n    ";
    }
    __eta.res += "  </ul>\n";
  }
  __eta.res += "\n";
  if (it.params.scope?.includes("offline_access")) {
    __eta.res +=
      "  <li>\n  the client is asking to have offline access to this authorization\n    ";
    if (!it.details.missingOIDCScope || !it.details.missingOIDCScope.includes("offline_access")) {
      __eta.res += "      (which you've previously granted)\n    ";
    }
    __eta.res += "  </li>\n";
  }
  __eta.res += '\n</ul>\n\n<form autocomplete="off" action="';
  __eta.res += __eta.e(it.submitUrl);
  __eta.res +=
    '" method="post">\n  <input type="hidden" name="prompt" value="consent"/>\n  <button autofocus type="submit" class="login login-submit">Continue</button>\n</form>\n';

  if (__eta.layout) {
    __eta.res = include(__eta.layout, { ...it, body: __eta.res, ...__eta.layoutData });
  }

  return __eta.res;
}
