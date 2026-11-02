import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { stripComments } from '../../tools/strip-comments.js';

describe('publish-time comment stripping', () => {
  const lineTerminators = [
    ['LF', '\n'],
    ['CR', '\r'],
    ['CRLF', '\r\n'],
    ['LINE SEPARATOR', '\u2028'],
    ['PARAGRAPH SEPARATOR', '\u2029'],
  ];

  it('keeps the tokens either side of a comment apart', { timeout: 3000 }, () => {
    for (const [source, expected] of [
      ['const x = typeof/* c */foo;', 'const x = typeof foo;'],
      ['return/* c */x;', 'return x;'],
      ['const a = 1;/* c */const b = 2;', 'const a = 1; const b = 2;'],
      ['a/* c */+/* c */b', 'a + b'],
      ['new/* c */Foo()', 'new Foo()'],
    ]) {
      assert.equal(stripComments(source), expected);
    }
  });

  it('preserves every ECMAScript line terminator', { timeout: 3000 }, () => {
    for (const [name, terminator] of lineTerminators) {
      const block = `return/*${terminator}*/1`;
      const line = `let value = 1; // comment${terminator}value = 2;\nreturn value`;

      assert.equal(stripComments(block), `return${terminator}1`, `${name} block`);
      assert.equal(stripComments(line), `let value = 1; ${terminator}value = 2;\nreturn value`, `${name} line`);
      assert.equal(Function(block)(), undefined, `${name} block source`);
      assert.equal(Function(stripComments(block))(), undefined, `${name} block output`);
      assert.equal(Function(stripComments(line))(), 2, `${name} line output`);
    }
  });

  it('leaves comment-like text inside strings, templates and regexes alone', { timeout: 3000 }, () => {
    // biome-ignore-start lint/suspicious/noTemplateCurlyInString: template source under test
    for (const source of [
      'const a = "/* not a comment */";',
      "const b = '// not a comment';",
      'const c = `// not a comment`;',
      'const d = /\\/\\*/;',
      'const e = `${x.replace(/\\/\\//g, "")}`;',
      'const f = `${c ? `v="${h(c)}"` : \'\'}`;',
    ]) {
      assert.equal(stripComments(source), source);
    }
    // biome-ignore-end lint/suspicious/noTemplateCurlyInString: template source under test
  });

  it('uses parser context to distinguish comments, regexes and division', { timeout: 3000 }, () => {
    for (const source of [
      'let hit = false; if (true) /[/*]/.test("/") && (hit = true); return hit;',
      'const x = async function () {} / /[/*]/.test("/"); /* remove */ return Number.isNaN(x);',
      'let x = 6; x++ / /[/*]/.test("/"); /* remove */ return x === 7;',
    ]) {
      const stripped = stripComments(source);

      assert.ok(!(stripped.includes('remove')));
      assert.equal(Function(source)(), true);
      assert.equal(Function(stripped)(), true);
    }
  });

  it('preserves hashbang contents', { timeout: 3000 }, () => {
    const source = '#!/usr/bin/env node /* part of hashbang\n'
      + 'const matched = /[/*]/.test("/"); /* remove */';
    const stripped = stripComments(source);

    assert.equal(stripped.startsWith('#!/usr/bin/env node /* part of hashbang\n'), true);
    assert.ok(!(stripped.includes('remove')));
  });

  it('removes what it is meant to', { timeout: 3000 }, () => {
    assert.equal(stripComments('/**\n * jsdoc\n */\nconst x = 1;'), '\n\n\nconst x = 1;');
    assert.equal(stripComments('/** jsdoc */\nconst x = 1;'), ' \nconst x = 1;');
    assert.equal(stripComments('const x = 1; // trailing'), 'const x = 1; ');
  });
});
