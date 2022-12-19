import htmlSafe from './html_safe.js';

export function input(action, csrfToken, code, charset) {
  const attributes = charset === 'digits' ? 'pattern="[0-9]*" inputmode="numeric" ' : '';

  return `<form id="op.deviceInputForm" novalidate method="post" action="${action}">
  <input type="hidden" name="xsrf" value="${csrfToken}"/>
  <input
    ${code ? `value="${htmlSafe(code)}" ` : ''}${attributes}type="text" name="user_code" placeholder="Enter code" onfocus="this.select(); this.onfocus = undefined;" autofocus autocomplete="off"></input>
  </form>`;
}

export function confirm(action, csrfToken, code, useBooleanConfirmation, confirmParamName) {
  return `<form id="op.deviceConfirmForm" method="post" action="${action}">
<input type="hidden" name="xsrf" value="${csrfToken}"/>
<input type="hidden" name="user_code" value="${htmlSafe(code)}"/>
${useBooleanConfirmation ? `<input type="hidden" name="${confirmParamName}" value="true"/>` : `<input type="hidden" name="${confirmParamName}" value="yes"/>`}
</form>`;
}
