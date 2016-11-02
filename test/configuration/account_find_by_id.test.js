'use strict';

const { Provider } = require('../../lib');
const { expect } = require('chai');

describe('default findById behavior', function () {
  it('returns a promise', function () {
    const provider = new Provider('http://localhost');
    const Account = provider.Account;

    expect(Account.findById('id') instanceof Promise).to.be.true;
  });

  it('resolves to an object with property and accountId property and claims function', function () {
    const provider = new Provider('http://localhost');
    const Account = provider.Account;

    return Account.findById('id').then((account) => {
      expect(account.accountId).to.equal('id');
      expect(account.claims).to.be.a('function');
      expect(account.claims()).to.eql({ sub: 'id' });
    });
  });
});
