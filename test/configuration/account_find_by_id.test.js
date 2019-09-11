const { expect } = require('chai');

const { Provider } = require('../../lib');

describe('default findAccount behavior', () => {
  it('returns a promise', () => {
    const provider = new Provider('http://localhost');
    const { Account } = provider;

    expect(Account.findAccount({}, 'id') instanceof Promise).to.be.true;
  });

  it('resolves to an object with property and accountId property and claims function', () => {
    const provider = new Provider('http://localhost');
    const { Account } = provider;

    return Account.findAccount({}, 'id').then(async (account) => {
      expect(account.accountId).to.equal('id');
      expect(await account.claims()).to.eql({ sub: 'id' });
    });
  });
});
