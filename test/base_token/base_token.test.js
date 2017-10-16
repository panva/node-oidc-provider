const sinon = require('sinon');
const { expect } = require('chai');
const bootstrap = require('../test_helper');
const base64url = require('base64url');

describe('BaseToken', () => {
  before(bootstrap(__dirname)); // provider

  afterEach(function () {
    this.adapter.find.reset();
    this.adapter.upsert.reset();
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
    const jti = token.substring(0, 48);
    const stored = this.adapter.syncFind(jti);
    const payload = JSON.parse(base64url.decode(stored.payload));
    payload.exp = 0;
    stored.payload = base64url(JSON.stringify(payload));
    expect(await this.provider.AccessToken.find(token)).to.be.undefined;
  });

  it('returns undefined for not found tokens', async function () {
    expect(await this.provider.AccessToken.find('MDQ0OWNjM2YtMzgzYi00M2FmLWJiNWItYWRhZjBjY2Y1ODY10FJ-UgHXVVUXSS-G5c8rn-YsfV4OlH5e1f_MneAvRyqwV6rIvC2Uq0')).to.be.undefined;
    expect(this.adapter.find.calledOnce).to.be.true;
  });

  it('assigns returned consumed prop', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = token.substring(0, 48);
    const stored = this.adapter.syncFind(jti);
    stored.consumed = true;
    expect(await this.provider.AccessToken.find(token)).to.have.property('consumed', true);
  });

  it('uses expiration for upsert from global settings if not specified in token values', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
    }).save();
    const jti = token.substring(0, 48);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 3600)).to.be.true;
  });

  it('uses expiration for upsert from token values', async function () {
    const token = await new this.provider.AccessToken({
      grantId: 'foo',
      expiresIn: 60,
    }).save();
    const jti = token.substring(0, 48);
    expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 60)).to.be.true;
  });
});
