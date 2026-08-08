import { expect } from 'chai';

import { stripComments } from '../../tools/strip-comments.js';

/*
 * tools/build.js runs this over every published file, so a bug here corrupts
 * the package silently - the output still parses, which is why `node --check`
 * in the build is not on its own enough.
 */
describe('publish-time comment stripping', () => {
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

  it('preserves the line count', () => {
    for (const source of [
      'a;\n/*\n *\n */\nb;',
      '// line\nconst x = 1; // trailing\n',
      'const t = `a\nb`; /* c */\n',
      'const x = 1; /* one line */ const y = 2;',
    ]) {
      expect(stripComments(source).split('\n')).to.have.lengthOf(source.split('\n').length);
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

  it('removes what it is meant to', () => {
    // a multi-line block leaves its newlines behind, a single-line block leaves
    // the one space that keeps the tokens apart
    expect(stripComments('/**\n * jsdoc\n */\nconst x = 1;')).to.equal('\n\n\nconst x = 1;');
    expect(stripComments('/** jsdoc */\nconst x = 1;')).to.equal(' \nconst x = 1;');
    expect(stripComments('const x = 1; // trailing')).to.equal('const x = 1; ');
  });
});
