'use strict';

module.exports = function getRespondAction(provider) {
  return function * respondAction(next) {
    this.oidc.uuid = this.params.grant;

    try {
      this.query = JSON.parse(this.cookies.get('_grant', {
        signed: true,
      }));
    } catch (err) {
      this.body = 'authentication request has expired';
      return;
    }

    let result;
    try {
      result = JSON.parse(this.cookies.get('_grant_result', {
        signed: true,
      }));
    } catch (err) {
      result = {};
    }

    if (result.login) {
      if (!result.login.remember) {
        // clear the existing session and create a fake one.
        delete this.oidc.session.acrValue;
        delete this.oidc.session.account;
        delete this.oidc.session.loginTs;

        this.oidc.session = new provider.Session();
      }

      this.oidc.session.acrValue = result.login.acr;
      this.oidc.session.account = result.login.account;
      this.oidc.session.loginTs = result.login.ts;
    }

    // TODO: finish this
    // if (result.consent) {
    //
    // }

    this.oidc.result = result;

    yield next;
  };
};
