import { describe, before, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';
import timekeeper from 'timekeeper';

import instance from '../../lib/helpers/weak_cache.js';
import withTimeout from '../with_timeout.js';
import bootstrap from '../test_helper.js';

const sinon = createSandbox();

describe('BaseToken', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  function spyOnAdapter() {
    fixture.adapter = fixture.TestAdapter.for('RefreshToken');
    sinon.spy(fixture.adapter, 'find');
    sinon.spy(fixture.adapter, 'upsert');
  }

  beforeEach(() => spyOnAdapter(), { timeout: 3000 });

  afterEach(() => timekeeper.reset(), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('handles legacy structured tokens', { timeout: 3000 }, async () => {
    const token = await new fixture.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = fixture.getTokenJti(token);
    fixture.adapter.syncUpdate(jti, {
      jwt: 'foo',
    });
    assert.equal(await fixture.provider.RefreshToken.find(token), undefined);
  });

  it('handles expired tokens', { timeout: 3000 }, async () => {
    const token = await new fixture.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = fixture.getTokenJti(token);
    fixture.adapter.syncUpdate(jti, {
      exp: 0,
    });
    assert.equal(await fixture.provider.RefreshToken.find(token), undefined);
  });

  it('handles invalid inputs', { timeout: 3000 }, async () => {
    for (const input of [true, Boolean, 1, Infinity, {}, [], new Set()]) {
      const result = await fixture.provider.RefreshToken.find(input);
      assert.equal(result, undefined);
    }
  });

  it('assigns returned consumed prop', { timeout: 3000 }, async () => {
    const token = await new fixture.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = fixture.getTokenJti(token);
    const stored = fixture.TestAdapter.for('RefreshToken').syncFind(jti);
    stored.consumed = true;
    ((actual) => { assert.ok('consumed' in Object(actual)); assert.equal(actual.consumed, true); })(await fixture.provider.RefreshToken.find(token));
  });

  it('uses expiration for upsert from global settings if not specified in token values', { timeout: 3000 }, async () => {
    const token = await new fixture.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = fixture.getTokenJti(token);
    assert.equal(fixture.adapter.upsert.calledWith(jti, sinon.match({}), 14 * 24 * 60 * 60), true);
  });

  it('uses expiration for upsert from token values', { timeout: 3000 }, async () => {
    const token = await new fixture.provider.RefreshToken({
      grantId: 'foo',
      expiresIn: 60,
    }).save();
    const jti = fixture.getTokenJti(token);
    assert.equal(fixture.adapter.upsert.calledWith(jti, sinon.match({}), 60), true);
  });

  it('rejects invalid TTL callback results with the configuration path', { timeout: 3000 }, async () => {
    const { ttl } = instance(fixture.provider).configuration;
    const original = ttl.RefreshToken;
    ttl.RefreshToken = () => 0;

    try {
      await assert.rejects(
        new fixture.provider.RefreshToken({ grantId: 'foo' }).save(),
        { name: 'TypeError', message: 'ttl.RefreshToken must return a positive integer' },
      );
    } finally {
      ttl.RefreshToken = original;
    }
  });

  it('resaves tokens with their actual remaining ttl passed to expiration', { timeout: 7000 }, async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      if (attempt > 0) spyOnAdapter();
      try {
        await withTimeout(async () => {
          let token = new fixture.provider.RefreshToken({
            grantId: 'foo',
          });
          const value = await token.save();
          const jti = fixture.getTokenJti(value);
          sinon.assert.calledWith(
            fixture.adapter.upsert.getCall(0),
            jti,
            sinon.match({}),
            sinon.match((ttl) => {
              assert.equal(typeof ttl, 'number');
              assert.ok(Math.abs(ttl - 14 * 24 * 60 * 60) <= 1);
              return true;
            }),
          );
          timekeeper.travel(((Date.now() / 1000 | 0) + 60) * 1000);
          token = await fixture.provider.RefreshToken.find(value);
          await token.save();
          sinon.assert.calledWith(
            fixture.adapter.upsert.getCall(1),
            jti,
            sinon.match({}),
            sinon.match((ttl) => {
              assert.equal(typeof ttl, 'number');
              assert.ok(Math.abs(ttl - (14 * 24 * 60 * 60 - 60)) <= 1);
              return true;
            }),
          );
        }, 3000);
        return;
      } catch (error) {
        if (attempt === 1) throw error;
      } finally {
        timekeeper.reset();
        sinon.restore();
      }
    }
  });

  it('additional save does not change the token value', { timeout: 3000 }, async () => {
    let token = new fixture.provider.RefreshToken({
      grantId: 'foo',
    });
    const first = await token.save();

    token = await fixture.provider.RefreshToken.find(first);
    assert.equal(token.scope, undefined);
    token.scope = 'openid profile';
    const second = await token.save();

    token = await fixture.provider.RefreshToken.find(first);
    assert.equal(token.scope, 'openid profile');
    token.scope = 'openid profile email';
    const third = await token.save();

    token = await fixture.provider.RefreshToken.find(first);
    assert.equal(token.scope, 'openid profile email');

    assert.equal(second, first);
    assert.equal(third, second);
  });

  it('rethrows adapter#find errors from session bound tokens looking up the session', { timeout: 3000 }, async () => {
    const token = new fixture.provider.RefreshToken({
      expiresWithSession: true,
      sessionUid: 'foo',
    });
    const value = await token.save();
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(fixture.TestAdapter.for('Session'), 'findByUid').callsFake(async () => { throw adapterThrow; });
    return assert.rejects(fixture.provider.RefreshToken.find(value), (err) => {
      fixture.TestAdapter.for('Session').findByUid.restore();
      assert.equal(err, adapterThrow);
      return true;
    });
  });

  it('consumed token save saves consumed', { timeout: 3000 }, async () => {
    let token = new fixture.provider.AuthorizationCode({
      grantId: 'foo',
      consumed: true,
    });
    const first = await token.save();

    token = await fixture.provider.AuthorizationCode.find(first);
    assert.equal(token.consumed, true);
  });

  it('rethrows adapter#findByUserCode errors (Device Code)', { timeout: 3000 }, async () => {
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(fixture.TestAdapter.for('DeviceCode'), 'findByUserCode').callsFake(async () => { throw adapterThrow; });
    return assert.rejects(fixture.provider.DeviceCode.findByUserCode('123-456-789').then(() => {
      fixture.TestAdapter.for('DeviceCode').findByUserCode.restore();
    }), (err) => {
      fixture.TestAdapter.for('DeviceCode').findByUserCode.restore();
      assert.equal(err, adapterThrow);
      return true;
    });
  });
});
