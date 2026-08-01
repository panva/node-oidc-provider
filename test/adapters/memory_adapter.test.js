import { expect } from 'chai';
import sinon from 'sinon';

describe('MemoryAdapter', () => {
  let clock;
  let MemoryAdapter;

  before(async () => {
    ({ default: MemoryAdapter } = await import('../../lib/adapters/memory_adapter.js?expiration-tests'));
  });

  beforeEach(() => {
    clock = sinon.useFakeTimers();
  });

  afterEach(() => {
    clock.restore();
  });

  it('expires primary entries', async () => {
    const adapter = new MemoryAdapter('AccessToken');
    const payload = { accountId: 'account' };

    await adapter.upsert('token', payload, 1);
    expect(await adapter.find('token')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.find('token')).to.be.undefined;
  });

  it('expires session uid indexes', async () => {
    const adapter = new MemoryAdapter('Session');
    const payload = { uid: 'uid' };

    await adapter.upsert('session', payload, 1);
    expect(await adapter.findByUid('uid')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.findByUid('uid')).to.be.undefined;
  });

  it('expires user code indexes', async () => {
    const adapter = new MemoryAdapter('DeviceCode');
    const payload = { userCode: 'code' };

    await adapter.upsert('device', payload, 1);
    expect(await adapter.findByUserCode('code')).to.equal(payload);

    clock.tick(1001);
    expect(await adapter.findByUserCode('code')).to.be.undefined;
  });
});
