import { expect } from 'chai';
import QuickLRU from 'quick-lru';
import sinon from 'sinon';

import MemoryAdapter from '../../lib/adapters/memory_adapter.js';

describe('MemoryAdapter', () => {
  let clock;
  let store;

  beforeEach(() => {
    clock = sinon.useFakeTimers();
    store = new QuickLRU({ maxSize: 1000 });
  });

  afterEach(() => {
    clock.restore();
  });

  it('expires primary entries', async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { accountId: 'account' };

    await adapter.upsert('token', payload, 1);
    expect(await adapter.find('token')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.find('token')).to.be.undefined;
  });

  it('expires session uid indexes', async () => {
    const adapter = new MemoryAdapter('Session', store);
    const payload = { uid: 'uid' };

    await adapter.upsert('session', payload, 1);
    expect(await adapter.findByUid('uid')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.findByUid('uid')).to.be.undefined;
  });

  it('expires user code indexes', async () => {
    const adapter = new MemoryAdapter('DeviceCode', store);
    const payload = { userCode: 'code' };

    await adapter.upsert('device', payload, 1);
    expect(await adapter.findByUserCode('code')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.findByUserCode('code')).to.be.undefined;
  });

  it('deduplicates grant members on repeated upsert', async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { grantId: 'grant', jti: 'token' };

    await adapter.upsert('token', payload, 60);
    await adapter.upsert('token', payload, 60);

    expect(store.get('grant:grant')).to.be.instanceOf(Map).and.have.length(1);
  });

  it('moves grant membership when a record is updated', async () => {
    const adapter = new MemoryAdapter('AccessToken', store);
    const payload = { grantId: 'second', jti: 'token' };

    await adapter.upsert('token', { grantId: 'first', jti: 'token' }, 60);
    await adapter.upsert('token', payload, 60);
    await adapter.revokeByGrantId('first');

    expect(await adapter.find('token')).to.equal(payload);
    expect(store.has('grant:first')).to.be.false;

    await adapter.revokeByGrantId('second');
    expect(await adapter.find('token')).to.be.undefined;
  });

  it('updates session uid and user code indexes', async () => {
    const session = new MemoryAdapter('Session', store);
    const device = new MemoryAdapter('DeviceCode', store);
    const sessionPayload = { uid: 'new-uid' };
    const devicePayload = { userCode: 'new-code' };

    await session.upsert('session', { uid: 'old-uid' }, 60);
    await session.upsert('session', sessionPayload, 60);
    await device.upsert('device', { userCode: 'old-code' }, 60);
    await device.upsert('device', devicePayload, 60);

    expect(await session.findByUid('old-uid')).to.be.undefined;
    expect(await session.findByUid('new-uid')).to.equal(sessionPayload);
    expect(await device.findByUserCode('old-code')).to.be.undefined;
    expect(await device.findByUserCode('new-code')).to.equal(devicePayload);
  });

  it('removes secondary and grant indexes when records are destroyed', async () => {
    const session = new MemoryAdapter('Session', store);
    const device = new MemoryAdapter('DeviceCode', store);

    await session.upsert('session', { uid: 'uid' }, 60);
    await device.upsert('device', { grantId: 'grant', jti: 'device', userCode: 'code' }, 60);
    await session.destroy('session');
    await device.destroy('device');

    expect(await session.findByUid('uid')).to.be.undefined;
    expect(await device.findByUserCode('code')).to.be.undefined;
    expect(store.has('grant:grant')).to.be.false;
  });

  it('does not delete a secondary index reassigned to another record', async () => {
    const adapter = new MemoryAdapter('DeviceCode', store);
    const replacement = { userCode: 'code' };

    await adapter.upsert('first', { userCode: 'code' }, 60);
    await adapter.upsert('second', replacement, 60);
    await adapter.destroy('first');

    expect(await adapter.findByUserCode('code')).to.equal(replacement);
  });

  it('revokes every model and its secondary indexes for a grant', async () => {
    const accessToken = new MemoryAdapter('AccessToken', store);
    const refreshToken = new MemoryAdapter('RefreshToken', store);
    const deviceCode = new MemoryAdapter('DeviceCode', store);

    await accessToken.upsert('access', { grantId: 'grant', jti: 'access' }, 60);
    await refreshToken.upsert('refresh', { grantId: 'grant', jti: 'refresh' }, 120);
    await deviceCode.upsert('device', {
      grantId: 'grant', jti: 'device', userCode: 'code',
    }, 30);
    await accessToken.revokeByGrantId('grant');

    expect(await accessToken.find('access')).to.be.undefined;
    expect(await refreshToken.find('refresh')).to.be.undefined;
    expect(await deviceCode.find('device')).to.be.undefined;
    expect(await deviceCode.findByUserCode('code')).to.be.undefined;
    expect(store.has('grant:grant')).to.be.false;
  });

  it('expires a grant index with its longest-lived member', async () => {
    const adapter = new MemoryAdapter('AccessToken', store);

    await adapter.upsert('short', { grantId: 'grant', jti: 'short' }, 1);
    await adapter.upsert('long', { grantId: 'grant', jti: 'long' }, 2);

    clock.tick(1001);
    expect(store.has('grant:grant')).to.be.true;

    clock.tick(1000);
    expect(store.has('grant:grant')).to.be.false;
  });
});
