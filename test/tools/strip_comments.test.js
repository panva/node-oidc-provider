import { expect } from 'chai';

import { stripComments } from '../../tools/strip-comments.js';

describe('publish-time comment stripping', () => {
  const lineTerminators = [
    ['LF', '\n'],
    ['CR', '\r'],
    ['CRLF', '\r\n'],
    ['LINE SEPARATOR', '\u2028'],
    ['PARAGRAPH SEPARATOR', '\u2029'],
  ];

  it('keeps the tokens either side of a comment apart', () => {
    for (const [source, expected] of [
      ['const x = typeof/* c */foo;', 'const x = typeof foo;'],
      ['return/* c */x;', 'return x;'],
      ['const a = 1;/* c */const b = 2;', 'const a = 1; const b = 2;'],
      ['a/* c */+/* c */b', 'a + b'],
      ['new/* c */Foo()', 'new Foo()'],
    ]) {
      expect(stripComments(source)).to.equal(expected);
    }
  });

  it('preserves every ECMAScript line terminator', () => {
    for (const [name, terminator] of lineTerminators) {
      const block = `return/*${terminator}*/1`;
      const line = `let value = 1; // comment${terminator}value = 2;\nreturn value`;

      expect(stripComments(block), `${name} block`).to.equal(`return${terminator}1`);
      expect(stripComments(line), `${name} line`)
        .to.equal(`let value = 1; ${terminator}value = 2;\nreturn value`);
      expect(Function(block)(), `${name} block source`).to.be.undefined;
      expect(Function(stripComments(block))(), `${name} block output`).to.be.undefined;
      expect(Function(stripComments(line))(), `${name} line output`).to.equal(2);
    }
  });

  it('leaves comment-like text inside strings, templates and regexes alone', () => {
    // biome-ignore-start lint/suspicious/noTemplateCurlyInString: template source under test
    for (const source of [
      'const a = "/* not a comment */";',
      "const b = '// not a comment';",
      'const c = `// not a comment`;',
      'const d = /\\/\\*/;',
      'const e = `${x.replace(/\\/\\//g, "")}`;',
      'const f = `${c ? `v="${h(c)}"` : \'\'}`;',
    ]) {
      expect(stripComments(source)).to.equal(source);
    }
    // biome-ignore-end lint/suspicious/noTemplateCurlyInString: template source under test
  });

  it('uses parser context to distinguish comments, regexes and division', () => {
    for (const source of [
      'let hit = false; if (true) /[/*]/.test("/") && (hit = true); return hit;',
      'const x = async function () {} / /[/*]/.test("/"); /* remove */ return Number.isNaN(x);',
      'let x = 6; x++ / /[/*]/.test("/"); /* remove */ return x === 7;',
    ]) {
      const stripped = stripComments(source);

      expect(stripped).not.to.include('remove');
      expect(Function(source)()).to.be.true;
      expect(Function(stripped)()).to.be.true;
    }
  });

  it('preserves hashbang contents', () => {
    const source = '#!/usr/bin/env node /* part of hashbang\n'
      + 'const matched = /[/*]/.test("/"); /* remove */';
    const stripped = stripComments(source);

    expect(stripped.startsWith('#!/usr/bin/env node /* part of hashbang\n')).to.be.true;
    expect(stripped).not.to.include('remove');
  });

  it('removes what it is meant to', () => {
    expect(stripComments('/**\n * jsdoc\n */\nconst x = 1;')).to.equal('\n\n\nconst x = 1;');
    expect(stripComments('/** jsdoc */\nconst x = 1;')).to.equal(' \nconst x = 1;');
    expect(stripComments('const x = 1; // trailing')).to.equal('const x = 1; ');
  });
});
