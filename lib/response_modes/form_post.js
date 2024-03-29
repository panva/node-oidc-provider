import htmlSafe from '../helpers/html_safe.js';
import pushInlineSha from '../helpers/script_src_sha.js';

const statusCodes = new Set([200, 400, 500]);

export default function formPost(ctx, action, inputs) {
  ctx.type = 'html';

  if (!statusCodes.has(ctx.status)) {
    ctx.status = 'error' in inputs ? 400 : 200;
  }

  const formInputs = Object.entries(inputs)
    .map(([key, value]) => `<input type="hidden" name="${key}" value="${htmlSafe(value)}"/>`)
    .join('\n');

  ctx.body = `<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Submitting Callback</title>
  <script>${pushInlineSha(ctx, `
    document.addEventListener('DOMContentLoaded', function () { document.forms[0].submit() });
  `)}</script>
</head>
<body>
  <form method="post" action="${htmlSafe(action)}">
    ${formInputs}
    <noscript>
      Your browser does not support JavaScript or you've disabled it.<br/>
      <button autofocus type="submit">Continue</button>
    </noscript>
  </form>
</body>
</html>`;
}
