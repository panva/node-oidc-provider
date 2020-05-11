const htmlSafe = require('../helpers/html_safe');

const statusCodes = new Set([200, 400, 500]);

module.exports = function formPost(ctx, action, inputs) {
  ctx.type = 'html';

  if (!statusCodes.has(ctx.status)) {
    ctx.status = 'error' in inputs ? 400 : 200;
  }

  const formInputs = Object.entries(inputs)
    .map(([key, value]) => `<input type="hidden" name="${key}" value="${htmlSafe(value)}"/>`)
    .join('\n');

  ctx.body = `<!DOCTYPE html>
<head>
  <title>Submitting Callback</title>
  <script>
    document.addEventListener('DOMContentLoaded', function () { document.forms[0].submit() });
  </script>
</head>
<body>
  <form method="post" action="${action}">
    ${formInputs}
    <noscript>
      Your browser does not support JavaScript or you've disabled it.<br/>
      <button autofocus type="submit">Continue</button>
    </noscript>
  </form>
</body>
</html>`;
};
