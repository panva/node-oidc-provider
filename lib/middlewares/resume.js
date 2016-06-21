'use strict';

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return function * resumeAction(next) {
    this.oidc.uuid = this.params.grant;

    try {
      this.query = j(this.cookies.get('_grant', provider.configuration.cookies.short));
    } catch (err) {
      this.body = 'authentication request has expired';
      this.status = 400;
      return;
    }

    let result;
    try {
      result = j(this.cookies.get('_grant_result', provider.configuration.cookies.short));
    } catch (err) {
      result = {};
    }

    if (result.login) {
      if (!result.login.remember) {
        // clear the existing session and create a fake one.
        yield this.oidc.session.destroy();
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
