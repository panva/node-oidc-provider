import { expect } from 'chai';
import jsesc from 'jsesc';

/*
 * lib/response_modes/web_message.js used to serialise the web_message payload
 * with jsesc's `{ json: true, isScriptContext: true }` mode. jsesc is kept as a
 * devDependency so the replacement can be held to it.
 *
 * The replacement is deliberately not byte-identical: it escapes `<`, `>` and
 * `&` unconditionally where jsesc only escapes them in the specific sequences
 * it recognises. What must hold is that both encode the same VALUE, and that
 * the replacement leaves nothing an HTML parser can act on.
 */

const SCRIPT_UNSAFE = /[<>&\u2028\u2029]/g;
const escapeScriptContext = (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0').toUpperCase()}`;
const serialise = (value) => JSON.stringify(value).replace(SCRIPT_UNSAFE, escapeScriptContext);

const HOSTILE = [
  '</script><img src=x onerror=alert(1)>',
  '</ScRiPt >',
  '<!--',
  '-->',
  '<!--<script>',
  '<script>alert(1)</script>',
  '\u2028\u2029',
  '\u0000\u001f\u007f',
  // biome-ignore lint/suspicious/noTemplateCurlyInString: deliberate hostile payload
  '`${alert(1)}`',
  '\\u003c/script>',
  '&lt;/script&gt;',
  '"\'\\',
  '\ud83d\ude00',
  'ünïcödé',
  '',
];

describe('web_message payload serialisation', () => {
  it('encodes the same value as jsesc for hostile payloads', () => {
    for (const value of HOSTILE) {
      const payload = { response: { code: value, state: value }, redirect_uri: value };
      const mine = serialise(payload);
      const theirs = jsesc(payload, { json: true, isScriptContext: true });
      expect(JSON.parse(mine)).to.deep.equal(JSON.parse(theirs));
      expect(JSON.parse(mine)).to.deep.equal(payload);
    }
  });

  it('encodes the same value as jsesc for every BMP code point', () => {
    for (let cp = 0; cp <= 0xffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogates are not valid JSON input
      const value = String.fromCodePoint(cp);
      const payload = { response: { code: value }, redirect_uri: value };
      const mine = JSON.parse(serialise(payload)).response.code;
      if (mine !== value) throw new Error(`round-trip failed at U+${cp.toString(16).toUpperCase()}`);
      const theirs = JSON.parse(jsesc(payload, { json: true, isScriptContext: true })).response.code;
      if (mine !== theirs) throw new Error(`jsesc mismatch at U+${cp.toString(16).toUpperCase()}`);
    }
  });

  it('leaves nothing for an HTML parser to act on', () => {
    for (const value of HOSTILE) {
      const out = serialise({ response: { code: value }, redirect_uri: value });
      expect(out).not.to.match(/[<>&\u2028\u2029]/);
      expect(out.toLowerCase()).not.to.include('</script');
      expect(out).not.to.include('<!--');
    }
  });

  it('is evaluated identically to jsesc by the JavaScript parser', () => {
    for (const value of HOSTILE) {
      const payload = { response: { code: value }, redirect_uri: value };
      const mine = new Function(`return (${serialise(payload)});`)();
      const theirs = new Function(`return (${jsesc(payload, { json: true, isScriptContext: true })});`)();
      expect(mine).to.deep.equal(theirs);
      expect(mine).to.deep.equal(payload);
    }
  });
});
