import { describe, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import QuickLRU from 'quick-lru';
import sinon from 'sinon';

import MemoryAdapter from '../../lib/adapters/memory_adapter.js';

describe('MemoryAdapter', () => {
  let clock;
  let store;

  beforeEach(() => {
    clock = sinon.useFakeTimers();
    store = new QuickLRU({ maxSize: 1000 });
  }, { timeout: 3000 });

  afterEach(() => {
    clock.restore();
  }, { timeout: 3000 });

  it('expires primary entries', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { accountId: 'account' };

    await adapter.upsert('token', payload, 1);
    assert.equal(await adapter.find('token'), payload);

    clock.tick(1001);
    assert.equal(await adapter.find('token'), undefined);
  });

  it('expires session uid indexes', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('Session', store);
    const payload = { uid: 'uid' };

    await adapter.upsert('session', payload, 1);
    assert.equal(await adapter.findByUid('uid'), payload);

    clock.tick(1001);
    assert.equal(await adapter.findByUid('uid'), undefined);
  });

  it('expires user code indexes', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('DeviceCode', store);
    const payload = { userCode: 'code' };

    await adapter.upsert('device', payload, 1);
    assert.equal(await adapter.findByUserCode('code'), payload);

    clock.tick(1001);
    assert.equal(await adapter.findByUserCode('code'), undefined);
  });

  it('deduplicates grant members on repeated upsert', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { grantId: 'grant', jti: 'token' };

    await adapter.upsert('token', payload, 60);
    await adapter.upsert('token', payload, 60);

    ((actual) => { assert.ok(actual instanceof Map); assert.equal(actual.size, 1); })(store.get('grant:grant'));
  });

  it('moves grant membership when a record is updated', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { grantId: 'second', jti: 'token' };

    await adapter.upsert('token', { grantId: 'first', jti: 'token' }, 60);
    await adapter.upsert('token', payload, 60);
    await adapter.revokeByGrantId('first');

    assert.equal(await adapter.find('token'), payload);
    assert.equal(store.has('grant:first'), false);

    await adapter.revokeByGrantId('second');
    assert.equal(await adapter.find('token'), undefined);
  });

  it('updates session uid and user code indexes', { timeout: 3000 }, async () => {
    const session = new MemoryAdapter('Session', store);
    const device = new MemoryAdapter('DeviceCode', store);
    const sessionPayload = { uid: 'new-uid' };
    const devicePayload = { userCode: 'new-code' };

    await session.upsert('session', { uid: 'old-uid' }, 60);
    await session.upsert('session', sessionPayload, 60);
    await device.upsert('device', { userCode: 'old-code' }, 60);
    await device.upsert('device', devicePayload, 60);

    assert.equal(await session.findByUid('old-uid'), undefined);
    assert.equal(await session.findByUid('new-uid'), sessionPayload);
    assert.equal(await device.findByUserCode('old-code'), undefined);
    assert.equal(await device.findByUserCode('new-code'), devicePayload);
  });

  it('removes secondary and grant indexes when records are destroyed', { timeout: 3000 }, async () => {
    const session = new MemoryAdapter('Session', store);
    const device = new MemoryAdapter('DeviceCode', store);

    await session.upsert('session', { uid: 'uid' }, 60);
    await device.upsert('device', { grantId: 'grant', jti: 'device', userCode: 'code' }, 60);
    await session.destroy('session');
    await device.destroy('device');

    assert.equal(await session.findByUid('uid'), undefined);
    assert.equal(await device.findByUserCode('code'), undefined);
    assert.equal(store.has('grant:grant'), false);
  });

  it('does not delete a secondary index reassigned to another record', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('DeviceCode', store);
    const replacement = { userCode: 'code' };

    await adapter.upsert('first', { userCode: 'code' }, 60);
    await adapter.upsert('second', replacement, 60);
    await adapter.destroy('first');

    assert.equal(await adapter.findByUserCode('code'), replacement);
  });

  it('revokes every model and its secondary indexes for a grant', { timeout: 3000 }, async () => {
    const accessToken = new MemoryAdapter('AccessToken', store);
    const refreshToken = new MemoryAdapter('RefreshToken', store);
    const deviceCode = new MemoryAdapter('DeviceCode', store);

    await accessToken.upsert('access', { grantId: 'grant', jti: 'access' }, 60);
    await refreshToken.upsert('refresh', { grantId: 'grant', jti: 'refresh' }, 120);
    await deviceCode.upsert('device', {
      grantId: 'grant', jti: 'device', userCode: 'code',
    }, 30);
    await accessToken.revokeByGrantId('grant');

    assert.equal(await accessToken.find('access'), undefined);
    assert.equal(await refreshToken.find('refresh'), undefined);
    assert.equal(await deviceCode.find('device'), undefined);
    assert.equal(await deviceCode.findByUserCode('code'), undefined);
    assert.equal(store.has('grant:grant'), false);
  });

  it('expires a grant index with its longest-lived member', { timeout: 3000 }, async () => {
    const adapter = new MemoryAdapter('AccessToken', store);

    await adapter.upsert('short', { grantId: 'grant', jti: 'short' }, 1);
    await adapter.upsert('long', { grantId: 'grant', jti: 'long' }, 2);

    clock.tick(1001);
    assert.equal(store.has('grant:grant'), true);

    clock.tick(1000);
    assert.equal(store.has('grant:grant'), false);
  });

  it('applies clock tolerance to entries and indexes', { timeout: 3000 }, async () => {
    const session = new MemoryAdapter('Session', store, 1);
    const device = new MemoryAdapter('DeviceCode', store, 1);
    const sessionPayload = { uid: 'uid' };
    const devicePayload = { grantId: 'grant', jti: 'device', userCode: 'code' };

    await session.upsert('session', sessionPayload, 1);
    await device.upsert('device', devicePayload, 1);

    clock.tick(1001);
    assert.equal(await session.findByUid('uid'), sessionPayload);
    assert.equal(await device.findByUserCode('code'), devicePayload);
    assert.equal(store.has('grant:grant'), true);

    clock.tick(1000);
    assert.equal(await session.findByUid('uid'), undefined);
    assert.equal(await device.findByUserCode('code'), undefined);
    assert.equal(store.has('grant:grant'), false);
  });
});
