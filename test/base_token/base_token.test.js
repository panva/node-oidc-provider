const sinon = require('sinon');
const { expect } = require('chai');
const timekeeper = require('timekeeper');

const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('BaseToken', () => {
  before(bootstrap(__dirname));

  afterEach(function () {
    this.adapter.find.resetHistory();
    this.adapter.upsert.resetHistory();
    timekeeper.reset();
  });

  beforeEach(function () {
    this.adapter = this.TestAdapter.for('RefreshToken');
    sinon.spy(this.adapter, 'find');
    sinon.spy(this.adapter, 'upsert');
  });

  afterEach(function () {
    this.adapter.find.restore();
    this.adapter.upsert.restore();
  });

  it('handles expired tokens', async function () {
    const token = await new this.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    this.adapter.syncUpdate(jti, {
      exp: 0,
    });
    expect(await this.provider.RefreshToken.find(token)).to.be.undefined;
  });

  it('handles invalid inputs', async function () {
    for (const input of [true, Boolean, 1, Infinity, {}, [], new Set()]) { // eslint-disable-line no-restricted-syntax, max-len
      const result = await this.provider.RefreshToken.find(input); // eslint-disable-line no-await-in-loop, max-len
      expect(result).to.be.undefined;
    }
  });

  it('returns undefined for not found tokens', async function () {
    expect(await this.provider.RefreshToken.find('.eyJqdGkiOiJ6d1FXa2pBUzhQZks1WEUyTTEyTTcifQ.')).to.be.undefined;
    expect(this.adapter.find.calledOnce).to.be.true;
  });

  it('assigns returned consumed prop', async function () {
    const token = await new this.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    const stored = this.adapter.syncFind(jti);
    stored.consumed = true;
    expect(await this.provider.RefreshToken.find(token)).to.have.property('consumed', true);
  });

  it('uses expiration for upsert from global settings if not specified in token values', async function () {
    const token = await new this.provider.RefreshToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 14 * 24 * 60 * 60)).to.be.true;
  });

  it('uses expiration for upsert from token values', async function () {
    const token = await new this.provider.RefreshToken({
      grantId: 'foo',
      expiresIn: 60,
    }).save();
    const jti = this.getTokenJti(token);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 60)).to.be.true;
  });

  it('resaves tokens with their actual remaining ttl passed to expiration', async function () {
    let token = new this.provider.RefreshToken({
      grantId: 'foo',
    });
    const value = await token.save();
    const jti = this.getTokenJti(value);
    sinon.assert.calledWith(
      this.adapter.upsert.getCall(0),
      jti,
      sinon.match({}),
      sinon.match((ttl) => {
        expect(ttl).to.be.closeTo(14 * 24 * 60 * 60, 1);
        return true;
      }),
    );
    timekeeper.travel(((Date.now() / 1000 | 0) + 60) * 1000); // eslint-disable-line no-bitwise
    token = await this.provider.RefreshToken.find(value);
    await token.save();
    sinon.assert.calledWith(
      this.adapter.upsert.getCall(1),
      jti,
      sinon.match({}),
      sinon.match((ttl) => {
        expect(ttl).to.be.closeTo((14 * 24 * 60 * 60 - 60), 1);
        return true;
      }),
    );
  });

  it('additional save does not change the token value', async function () {
    let token = new this.provider.RefreshToken({
      grantId: 'foo',
    });
    const first = await token.save();

    token = await this.provider.RefreshToken.find(first);
    expect(token.scope).to.be.undefined;
    token.scope = 'openid profile';
    const second = await token.save();

    token = await this.provider.RefreshToken.find(first);
    expect(token.scope).to.equal('openid profile');
    token.scope = 'openid profile email';
    const third = await token.save();

    token = await this.provider.RefreshToken.find(first);
    expect(token.scope).to.equal('openid profile email');

    expect(second).to.equal(first);
    expect(third).to.equal(second);
  });

  it('consumed token save saves consumed', async function () {
    let token = new this.provider.AuthorizationCode({
      grantId: 'foo',
      consumed: true,
    });
    const first = await token.save();

    token = await this.provider.AuthorizationCode.find(first);
    expect(token.consumed).to.be.true;
  });

  it('rethrows adapter#find errors (any token)', async function () {
    this.adapter.find.restore();
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(this.adapter, 'find').callsFake(async () => { throw adapterThrow; });
    await this.provider.RefreshToken.find('.eyJqdGkiOiJ6d1FXa2pBUzhQZks1WEUyTTEyTTcifQ.').then(fail, (err) => {
      expect(err).to.equal(adapterThrow);
    });
  });

  it('rethrows adapter#find errors from session bound tokens looking up the session', async function () {
    const token = new this.provider.RefreshToken({
      expiresWithSession: true,
      sessionUid: 'foo',
    });
    const value = await token.save();
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(this.TestAdapter.for('Session'), 'findByUid').callsFake(async () => { throw adapterThrow; });
    await this.provider.RefreshToken.find(value).then(fail, (err) => {
      this.TestAdapter.for('Session').findByUid.restore();
      expect(err).to.equal(adapterThrow);
    });
  });

  it('rethrows adapter#findByUserCode errors (Device Code)', async function () {
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(this.TestAdapter.for('DeviceCode'), 'findByUserCode').callsFake(async () => { throw adapterThrow; });
    await this.provider.DeviceCode.findByUserCode('123-456-789').then(() => {
      this.TestAdapter.for('DeviceCode').findByUserCode.restore();
      fail();
    }, (err) => {
      this.TestAdapter.for('DeviceCode').findByUserCode.restore();
      expect(err).to.equal(adapterThrow);
    });
  });
});
