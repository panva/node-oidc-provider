const htmlEscape = require('../helpers/html_escape');

module.exports = function formPost(ctx, action, inputs) {
  ctx.type = 'html';
  ctx.status = 200;

  const formInputs = Object.entries(inputs)
    .map(([key, value]) => `<input type="hidden" name="${key}" value="${htmlEscape(value)}"/>`)
    .join('\n');

  ctx.body = `<!DOCTYPE html>
<head>
  <title>Submitting Callback</title>
</head>
<body onload="javascript:document.forms[0].submit()">
  <form method="post" action="${action}">
    ${formInputs}
  </form>
</body>
</html>`;
};
