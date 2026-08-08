/*
 * Compiles tools/views/*.eta into lib/views/*.js.
 *
 * The views ship pre-compiled so that Eta is not a runtime dependency - see
 * lib/views/index.js, which supplies the little of Eta's runtime the compiled
 * templates call into. Eta is a devDependency and is used here, and by
 * test/views/eta_parity.test.js, which fails if the two ever drift apart.
 *
 * Only the statements come from Eta (compileBody); the surrounding function is
 * written out below, so the unused block/capture helpers Eta's full
 * compileToString emits never reach lib/.
 */

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Eta } from 'eta/core';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sources = join(root, 'tools', 'views');
const target = join(root, 'lib', 'views');

const eta = new Eta();

const IDENTIFIER = /^[$_\p{ID_Start}](?:[$\p{ID_Continue}]|\u200C|\u200D)*$/u;

function check(source) {
  execFileSync(process.execPath, ['--input-type=module', '--check', '-'], {
    input: source,
    stdio: 'pipe',
  });
}

function compile(name, source) {
  // Eta's statements go in verbatim, only shifted into the function body. No
  // brace-depth reindenting, no reflowing: these files are generated, biome.json
  // excludes them, and every transformation is somewhere a bug can hide.
  const body = eta.compileBody(eta.parse(source))
    .split('\n')
    .map((line) => (line ? `  ${line}` : ''))
    .join('\n');

  const wrap = (functionName) => `export default function ${functionName}(it, options) {
  const include = (template, data) => this.render(template, data, options);
  const includeAsync = (template, data) => this.renderAsync(template, data, options);

  const __eta = { res: "", e: this.config.escapeFunction, f: this.config.filterFunction };

  function layout(path, data) {
    __eta.layout = path;
    __eta.layoutData = data;
  }

${body}

  if (__eta.layout) {
    __eta.res = include(__eta.layout, { ...it, body: __eta.res, ...__eta.layoutData });
  }

  return __eta.res;
}
`;

  // Let the JavaScript parser decide whether an otherwise valid identifier is
  // reserved in a module. The shape check keeps a filename from injecting code.
  const preferred = IDENTIFIER.test(name) ? name : 'view';
  let compiled = wrap(preferred);
  try {
    check(compiled);
  } catch (err) {
    if (preferred === 'view') throw err;
    compiled = wrap('view');
    check(compiled);
  }
  return compiled;
}

for (const entry of readdirSync(sources)) {
  if (!entry.endsWith('.eta')) continue;

  const name = basename(entry, '.eta');
  const out = join(target, `${name}.js`);
  const compiled = compile(name, readFileSync(join(sources, entry), 'utf8'));

  // a new template, or a deleted output, has nothing to compare against
  let previous;
  try { previous = readFileSync(out, 'utf8'); } catch { previous = undefined; }

  writeFileSync(out, compiled);

  let state = 'created  ';
  if (previous !== undefined) state = compiled === previous ? 'unchanged' : 'updated  ';
  process.stdout.write(`${state} lib/views/${name}.js\n`);
}
