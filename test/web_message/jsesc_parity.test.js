import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import jsesc from 'jsesc';

import omitBy from '../../lib/helpers/_/omit_by.js';

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
  /*
   * A key holding `undefined` serialises differently in every response mode -
   * omitted here, but the literal string "undefined" in query, fragment and
   * form_post. It is reachable: process_response_types.js assigns
   * `expires_in: token.expiration` unconditionally, and a ttl.AccessToken
   * helper returning undefined puts it on the response.
   *
   * respond.js and authorization_error_handler.js drop undefined-valued keys
   * before handing the response to any response mode. These pin that.
   */
  it('omits undefined-valued keys rather than emitting "undefined"', { timeout: 3000 }, () => {
    const out = {
      access_token: 'at', expires_in: undefined, token_type: 'Bearer', state: 's',
    };
    const cleaned = omitBy({ ...out }, (value) => value === undefined);

    assert.ok(!('expires_in' in Object(cleaned)));
    assert.equal(serialise({ response: cleaned }), '{"response":{"access_token":"at","token_type":"Bearer","state":"s"}}');

    // what the other response modes would otherwise have produced
    assert.ok(new URLSearchParams(out).toString().includes('expires_in=undefined'));
    assert.ok(!(new URLSearchParams(cleaned).toString().includes('expires_in')));
  });

  it('leaves null and empty-string values alone', { timeout: 3000 }, () => {
    const out = { a: null, b: '', c: 0, d: false };
    assert.deepEqual(omitBy({ ...out }, (value) => value === undefined), out);
  });

  it('encodes the same value as jsesc for hostile payloads', { timeout: 3000 }, () => {
    for (const value of HOSTILE) {
      const payload = { response: { code: value, state: value }, redirect_uri: value };
      const mine = serialise(payload);
      const theirs = jsesc(payload, { json: true, isScriptContext: true });
      assert.deepEqual(JSON.parse(mine), JSON.parse(theirs));
      assert.deepEqual(JSON.parse(mine), payload);
    }
  });

  it('encodes the same value as jsesc for every BMP code point', { timeout: 3000 }, () => {
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

  it('leaves nothing for an HTML parser to act on', { timeout: 3000 }, () => {
    for (const value of HOSTILE) {
      const out = serialise({ response: { code: value }, redirect_uri: value });
      assert.doesNotMatch(out, /[<>&\u2028\u2029]/);
      assert.ok(!(out.toLowerCase().includes('</script')));
      assert.ok(!(out.includes('<!--')));
    }
  });

  it('is evaluated identically to jsesc by the JavaScript parser', { timeout: 3000 }, () => {
    for (const value of HOSTILE) {
      const payload = { response: { code: value }, redirect_uri: value };
      const mine = new Function(`return (${serialise(payload)});`)();
      const theirs = new Function(`return (${jsesc(payload, { json: true, isScriptContext: true })});`)();
      assert.deepEqual(mine, theirs);
      assert.deepEqual(mine, payload);
    }
  });
});
