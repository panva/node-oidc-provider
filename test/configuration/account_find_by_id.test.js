const { expect } = require('chai');

const Provider = require('../../lib');

describe('default findById behavior', () => {
  it('returns a promise', () => {
    const provider = new Provider('http://localhost');
    const { Account } = provider;

    expect(Account.findById({}, 'id') instanceof Promise).to.be.true;
  });

  it('resolves to an object with property and accountId property and claims function', () => {
    const provider = new Provider('http://localhost');
    const { Account } = provider;

    return Account.findById({}, 'id').then(async (account) => {
      expect(account.accountId).to.equal('id');
      expect(await account.claims()).to.eql({ sub: 'id' });
    });
  });
});
