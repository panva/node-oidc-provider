import { describe, it, } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';


const generator = fileURLToPath(new URL('../../docs/update-configuration.js', import.meta.url));
const testDirectory = fileURLToPath(new URL('.', import.meta.url));

function generate(mode = '--configuration-json') {
  return execFileSync(process.execPath, [generator, mode], {
    cwd: testDirectory,
    encoding: 'utf8',
  });
}

describe('configuration documentation metadata', () => {

  it('emits every block as deterministic JSON without rewriting documentation', { timeout: 3000 }, (t) => {
    const readme = new URL('../../docs/README.md', import.meta.url);
    if (!existsSync(readme)) {
      // docs/ is intentionally absent when test-dist runs against the package artifact.
      return t.skip();
    }
    const before = readFileSync(readme);
    const output = generate();
    const entries = JSON.parse(output);

    assert.equal(output, generate());
    assert.deepEqual(readFileSync(readme), before);
    ((actual) => { assert.ok(Array.isArray(actual)); assert.notEqual(actual.length, 0); })(entries);
    assert.equal(new Set(entries.map(({ path }) => path)).size, entries.length);

    ((actual) => { assert.ok("path" in Object(actual)); assert.equal(actual.path, 'adapter'); assert.ok("type" in Object(actual)); assert.equal(actual.type, 'AdapterConstructor | AdapterFactory'); assert.ok("title" in Object(actual)); assert.equal(actual.title, 'Storage Adapter'); assert.ok("important" in Object(actual)); assert.equal(actual.important, true); assert.ok("nodefault" in Object(actual)); assert.equal(actual.nodefault, true); })(entries[0]);
    assert.ok(entries[0].description.includes('Production deployments MUST provide a custom adapter'));
    assert.ok(entries[0].see.includes('[The expected interface](/example/my_adapter.js)'));
    ((actual) => { assert.ok("path" in Object(actual)); assert.equal(actual.path, 'subjectTypes'); })(entries.at(-1));

    ((actual) => { assert.ok("type" in Object(actual)); assert.equal(actual.type, '(ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean'); })(entries.find(({ path }) => path === 'clientBasedCORS'));
    ((actual) => { assert.equal(actual.placeholders.mustConfigure["0"], 'findAccount'); })(entries.find(({ path }) => path === 'findAccount'));
    ((actual) => { assert.ok("experimental" in Object(actual)); assert.equal(actual.experimental, true); })(entries.find(({ path }) => path === 'features.webMessageResponseMode'));
    ((actual) => { assert.ok("type" in Object(actual)); assert.equal(actual.type, 'ReadonlyArray<string | Buffer> | KeyGrip'); })(entries.find(({ path }) => path === 'cookies.keys'));

    for (const entry of entries) {
      ((actual) => { assert.equal(typeof actual, 'string'); assert.notEqual(actual.length, 0); })(entry.path);
      ((actual) => { assert.equal(typeof actual, 'string'); assert.notEqual(actual.length, 0); })(entry.type);
      if (entry.title) ((actual) => { assert.equal(typeof actual, 'string'); assert.notEqual(actual.length, 0); })(entry.title);
      if (entry.description) ((actual) => { assert.equal(typeof actual, 'string'); assert.notEqual(actual.length, 0); })(entry.description);
      if (entry.see) ((actual) => { assert.ok(Array.isArray(actual)); assert.notEqual(actual.length, 0); })(entry.see);
      if (entry.recommendations) {
        ((actual) => { assert.ok(Array.isArray(actual)); assert.notEqual(actual.length, 0); })(entry.recommendations);
      }
    }
  });
});
