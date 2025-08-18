import * as crypto from 'node:crypto';

export default function pushScriptSrcSha(ctx, script) {
  const csp = ctx.response.get('content-security-policy');
  if (csp) {
    const directives = csp.split(';').reduce((acc, directive) => {
      const [name, ...values] = directive.trim().split(/\s+/g);
      acc[name] = values;
      return acc;
    }, {});

    if (directives['script-src']) {
      const digest = crypto.hash('sha256', script, 'base64');
      directives['script-src'].push(`'sha256-${digest}'`);

      const replaced = Object.entries(directives).map(([name, values]) => [name, ...values].join(' ')).join(';');
      ctx.set('content-security-policy', replaced);
    }
  }
  return script;
}
