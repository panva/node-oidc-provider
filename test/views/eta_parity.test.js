import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { Eta } from 'eta/core';

import interactionTemplate from '../../lib/views/interaction.js';
import layoutTemplate from '../../lib/views/layout.js';
import loginTemplate from '../../lib/views/login.js';
import { escapeFunction, interaction, layout, login } from '../../lib/views/index.js';

/*
 * lib/views/index.js replaces the `eta` runtime dependency with a three line
 * shim. `eta` is kept as a devDependency so that the shim can be held to it.
 */

const eta = new Eta();

const cases = {
  interaction: [interactionTemplate, interaction],
  layout: [layoutTemplate, layout],
  login: [loginTemplate, login],
};

const HOSTILE = '<script>alert("xss")</script> & \'quoted\'    ünïcödé';

const locals = [
  { title: 'Sign-in', dbg: {}, uid: 'uid', client: {}, params: {}, details: {} },
  {
    title: HOSTILE,
    dbg: { params: HOSTILE, prompt: HOSTILE },
    uid: HOSTILE,
    client: { clientId: HOSTILE, clientName: HOSTILE, tosUri: HOSTILE, policyUri: HOSTILE },
    params: { login_hint: HOSTILE, scope: 'openid profile email' },
    details: { missingOIDCScope: ['openid', HOSTILE], missingOIDCClaims: [HOSTILE] },
    session: { accountId: HOSTILE },
    prompt: { name: 'consent', details: {} },
    body: HOSTILE,
  },
  {
    title: '', dbg: { params: '', prompt: '' }, uid: '', client: {}, params: {}, details: {}, session: undefined,
  },
];

describe('views render identically to eta', () => {
  for (const [name, [template, render]] of Object.entries(cases)) {
    for (const [i, data] of locals.entries()) {
      it(`${name} template, locals #${i}`, { timeout: 3000 }, () => {
        let expected;
        let actual;
        let expectedErr;
        let actualErr;

        try { expected = eta.render(template, data); } catch (err) { expectedErr = err; }
        try { actual = render(data); } catch (err) { actualErr = err; }

        if (expectedErr || actualErr) {
          assert.equal(actualErr?.constructor, expectedErr?.constructor);
          assert.equal(actualErr?.message, expectedErr?.message);
          return;
        }

        assert.equal(actual, expected);
      });
    }
  }

  // lib/views/*.js are pre-compiled eta output; their sources live in
  // tools/views/*.eta, which is not published. Nothing else links the two, so
  // this catches a .eta source being edited without recompiling - or a compiled
  // template being edited by hand.
  it('the checked-in compiled templates still match tools/views/*.eta', { timeout: 3000 }, () => {
    for (const [name, [template]] of Object.entries(cases)) {
      const source = readFileSync(new URL(`../../tools/views/${name}.eta`, import.meta.url), 'utf8');
      const recompiled = eta.compile(source);

      for (const [i, data] of locals.entries()) {
        let fromSource;
        let fromCheckedIn;
        let sourceErr;
        let checkedInErr;

        try { fromSource = eta.render(recompiled, data); } catch (err) { sourceErr = err; }
        try { fromCheckedIn = eta.render(template, data); } catch (err) { checkedInErr = err; }

        assert.equal(!!sourceErr, !!checkedInErr, `${name} locals #${i}`);
        if (!sourceErr) {
          assert.equal(fromSource, fromCheckedIn, `${name}.eta has drifted from lib/views/${name}.js (locals #${i})`);
        }
      }
    }
  });

  // a real Eta instance carries render/renderAsync as own class fields, so they
  // shadow Object.prototype. The shim must too, or the compiled templates'
  // `this.render` and `__eta.layout` reads walk the prototype chain.
  /*
   * The compiled templates read `this.render` and `__eta.layout`. Neither is an
   * own property of a bare object literal, so on a polluted Object.prototype
   * both resolve to whatever was planted there - and eta itself then CALLS it
   * and emits the return value as the page body. lib/views/index.js carries
   * render/renderAsync as own properties that throw, so the shim fails closed
   * instead. This asserts the shim's behaviour, not eta's.
   */
  it('does not resolve render or layout through Object.prototype', { timeout: 3000 }, () => {
    const called = [];
    const KEYS = ['render', 'renderAsync', 'layout', 'layoutData'];
    for (const key of KEYS) {
      Object.defineProperty(Object.prototype, key, {
        configurable: true,
        writable: true,
        enumerable: false,
        value: () => { called.push(key); return 'PWNED'; },
      });
    }

    try {
      for (const [name, [, render]] of Object.entries(cases)) {
        let out;
        try { out = render(locals[1]); } catch { out = undefined; } // failing closed is fine
        if (out !== undefined) assert.ok(!(out.includes('PWNED')), name);
      }
      assert.deepEqual(called, [], 'a polluted prototype function must never be called');
    } finally {
      for (const key of KEYS) delete Object.prototype[key];
    }
  });

  it('escapes every code point the same way eta does', { timeout: 3000 }, () => {
    const expected = eta.config.escapeFunction;
    for (let cp = 0; cp <= 0x10ffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogates
      const char = String.fromCodePoint(cp);
      if (escapeFunction(char) !== expected(char)) {
        throw new Error(`escape mismatch at U+${cp.toString(16).toUpperCase()}`);
      }
    }
  });

  it('coerces non-string values the same way eta does', { timeout: 3000 }, () => {
    const expected = eta.config.escapeFunction;
    for (const value of [0, 1, -1, 1.5, true, false, null, undefined, NaN, Infinity, [], [1, 2], {}, 1n, Symbol.iterator]) {
      let a;
      let b;
      try { a = escapeFunction(value); } catch (err) { a = `throws:${err.constructor.name}`; }
      try { b = expected(value); } catch (err) { b = `throws:${err.constructor.name}`; }
      assert.equal(a, b);
    }
  });

  it('filters non-string values the same way eta does', { timeout: 3000 }, () => {
    for (const value of [0, null, undefined, true, [1, 2], {}]) {
      assert.equal(String(value), eta.config.filterFunction(value));
    }
  });
});
