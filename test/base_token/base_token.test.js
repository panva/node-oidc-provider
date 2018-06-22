const sinon = require('sinon');
const { expect } = require('chai');
const timekeeper = require('timekeeper');
const { uniq } = require('lodash');

const bootstrap = require('../test_helper');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('BaseToken', () => {
  before(bootstrap(__dirname));

  afterEach(function () {
    this.adapter.find.resetHistory();
    this.adapter.upsert.resetHistory();
    timekeeper.reset();
  });

  before(function () {
    this.adapter = this.TestAdapter.for('AccessToken');
    sinon.spy(this.adapter, 'find');
    sinon.spy(this.adapter, 'upsert');
  });

  after(function () {
    this.adapter.find.restore();
    this.adapter.upsert.restore();
  });

  it('handles expired tokens', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    this.adapter.syncUpdate(jti, {
      exp: 0,
    });
    expect(await this.provider.AccessToken.find(token)).to.be.undefined;
  });

  it('returns undefined for not found tokens', async function () {
    expect(await this.provider.AccessToken.find('.eyJqdGkiOiJ6d1FXa2pBUzhQZks1WEUyTTEyTTcifQ.')).to.be.undefined;
    expect(this.adapter.find.calledOnce).to.be.true;
  });

  it('assigns returned consumed prop', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    const stored = this.adapter.syncFind(jti);
    stored.consumed = true;
    expect(await this.provider.AccessToken.find(token)).to.have.property('consumed', true);
  });

  it('uses expiration for upsert from global settings if not specified in token values', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = this.getTokenJti(token);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 3600)).to.be.true;
  });

  it('uses expiration for upsert from token values', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
      expiresIn: 60,
    }).save();
    const jti = this.getTokenJti(token);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 60)).to.be.true;
  });

  it('resaves tokens with their actual remaining ttl passed to expiration', async function () {
    let token = new this.provider.AccessToken({
      grantId: 'foo',
    });
    const value = await token.save();
    const jti = this.getTokenJti(value);
    timekeeper.travel(Date.now() + (60 * 1000));
    token = await this.provider.AccessToken.find(value);
    await token.save();
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 3600)).to.be.true;
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 3540)).to.be.true;
  });

  it('additional save does not change the token value', async function () {
    let token = new this.provider.AccessToken({
      grantId: 'foo',
    });
    const first = await token.save();

    token = await this.provider.AccessToken.find(first);
    expect(token.scope).to.be.undefined;
    token.scope = 'openid profile';
    const second = await token.save();

    token = await this.provider.AccessToken.find(first);
    expect(token.scope).to.equal('openid profile');
    token.scope = 'openid profile email';
    const third = await token.save();

    token = await this.provider.AccessToken.find(first);
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

  it('rethrows adapter#find errors', async function () {
    this.adapter.find.restore();
    const adapterThrow = new Error('adapter throw!');
    sinon.stub(this.adapter, 'find').callsFake(async () => { throw adapterThrow; });
    await this.provider.AccessToken.find('.eyJqdGkiOiJ6d1FXa2pBUzhQZks1WEUyTTEyTTcifQ.').then(fail, (err) => {
      expect(err).to.equal(adapterThrow);
    });
  });
});

describe('mixed formats for tokens', () => {
  before(bootstrap(__dirname, { config: 'base_token_mixed_formats' }));

  it('allows for formats to differ per token type', async function () {
    const models = [
      this.provider.BaseToken, this.provider.AccessToken,
      this.provider.RefreshToken, this.provider.AuthorizationCode,
    ];

    const generateTokenId = models.map(m => m.generateTokenId);
    const getTokenId = models.map(m => m.getTokenId);
    const verify = models.map(m => m.getTokenId);
    const getValueAndPayload = models.map(m => m.prototype.getValueAndPayload);

    expect(uniq(generateTokenId)).to.have.lengthOf(3);
    expect(uniq(getTokenId)).to.have.lengthOf(3);
    expect(uniq(verify)).to.have.lengthOf(3);
    expect(uniq(getValueAndPayload)).to.have.lengthOf(3);
  });
});
