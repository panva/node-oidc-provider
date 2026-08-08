import interactionTemplate from './interaction.js';
import layoutTemplate from './layout.js';
import loginTemplate from './login.js';

/*
 * The templates in this directory are pre-compiled Eta output (sources in
 * tools/views/*.eta). Rendering them needs nothing from Eta but its default
 * escape and filter functions, so the runtime dependency is replaced by the
 * three lines below.
 *
 * test/views/eta_parity.test.js asserts this renders byte-for-byte identically
 * to Eta itself.
 */

const ESCAPE = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeFunction(value) {
  const string = String(value);
  return /[&<>"']/.test(string) ? string.replace(/[&<>"']/g, (char) => ESCAPE[char]) : string;
}

/*
 * `render`/`renderAsync` are own properties, not omitted, for the same reason a
 * real Eta instance has them as own class fields: the compiled templates read
 * `this.render` and `__eta.layout`, and neither is an own property of a bare
 * object literal, so both would otherwise resolve through Object.prototype and
 * be reachable by prototype pollution. None of these templates uses a layout,
 * so being called at all is a bug - fail closed rather than call whatever was
 * found on the prototype chain.
 */
const unsupported = () => { throw new Error('views do not support includes or layouts'); };

const eta = {
  config: { escapeFunction, filterFunction: String },
  render: unsupported,
  renderAsync: unsupported,
};

const render = (template, locals) => template.call(eta, locals, { async: false });

export const interaction = (locals) => render(interactionTemplate, locals);

export const layout = (locals) => render(layoutTemplate, locals);

export const login = (locals) => render(loginTemplate, locals);
