import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';

import assertNoFocusedTests from './check-test-focus.js';

function fixture(t, source, name = 'focused.test.mjs') {
  const directory = mkdtempSync(join(tmpdir(), 'oidc-provider-test-focus-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = join(directory, name);
  writeFileSync(file, source);
  return file;
}

for (const call of [
  "it.only('focused', () => {});",
  "describe.only('focused', () => {});",
  "test['only']('focused', () => {});",
  'describe["only"]("focused", () => {});',
  "(condition ? it.only : it)('focused', () => {});",
  "it?.only('focused', () => {});",
  "test.only?.('focused', () => {});",
]) {
  it(`rejects focused calls: ${call}`, (t) => {
    const file = fixture(t, `// test file\n${call}\n`);
    assert.throws(() => assertNoFocusedTests([file]), { message: `focused test in ${file}:2` });
  });
}

for (const options of [
  '{ only: true }',
  "{ 'only': true }",
  '{ ["only"]: true }',
]) {
  it(`rejects focused options: ${options}`, (t) => {
    const file = fixture(t, `test('focused', ${options}, () => {});`);
    assert.throws(() => assertNoFocusedTests([file]), { message: `focused test in ${file}:1` });
  });
}

it('accepts ordinary tests, false options, comments, and strings', (t) => {
  const file = fixture(t, `
// it.only('example', () => {});
/* describe['only']('example', () => {}); */
const explanation = 'test.only and { only: true } must not be committed';
const fixture = { only: true };
object.only(fixture);
object.only({ only: true });
test('ordinary', { only: false }, () => {});
describe('nested', () => {
  it('ordinary', { 'only': false }, () => {});
});
`);
  assert.doesNotThrow(() => assertNoFocusedTests([file]));
});

for (const [declaration, call] of [
  ["import { it as caseTest } from 'node:test';", "caseTest.only('focused', () => {});"],
  ["import { describe as group } from 'node:test';", "group('focused', { only: true }, () => {});"],
  ["import nativeTest from 'node:test';", "nativeTest['only']('focused', () => {});"],
  ["import * as native from 'node:test';", "native.describe.only('focused', () => {});"],
]) {
  it(`rejects focused imported aliases: ${call}`, (t) => {
    const file = fixture(t, `${declaration}\n${call}`);
    assert.throws(() => assertNoFocusedTests([file]), { message: `focused test in ${file}:2` });
  });
}

it('checks every supplied file and reports the focused file', (t) => {
  const ordinary = fixture(t, "test('ordinary', () => {});", 'ordinary.test.mjs');
  const focused = fixture(t, "\n\nit.only('focused', () => {});", 'second.test.mjs');
  assert.throws(() => assertNoFocusedTests([ordinary, focused]), { message: `focused test in ${focused}:3` });
});

for (const call of ['t.runOnly(true)', 't["runOnly"](true)']) {
  it(`rejects focused context calls: ${call}`, (t) => {
    const file = fixture(t, `test('focused', (t) => { ${call}; });`);
    assert.throws(() => assertNoFocusedTests([file]), /focused test/);
  });
}
