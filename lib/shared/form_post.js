'use strict';

module.exports = function formPost(action, inputs) {
  this.type = 'html';
  this.status = 200;

  const formInputs = Object.keys(inputs)
    .map(name => `<input type="hidden" name="${name}" value="${inputs[name]}"/>`).join('\n');

  this.body = `<!DOCTYPE html>
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
