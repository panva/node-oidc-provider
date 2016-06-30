'use strict';

const j = JSON.parse;

module.exports = function getResumeAction(provider) {
  return function * resumeAction(next) {
    this.oidc.uuid = this.params.grant;

    const cookieOptions = provider.configuration('cookies.short');

    try {
      this.query = j(this.cookies.get('_grant', cookieOptions));
    } catch (err) {
      this.body = 'authentication request has expired';
      this.status = 400;
      return;
    }

    let result;
    try {
      result = j(this.cookies.get('_grant_result', cookieOptions));
    } catch (err) {
      result = {};
    }

    if (result.login) {
      if (!result.login.remember) {
        // clear the existing session and create a fake one.
        yield this.oidc.session.destroy();
        this.oidc.session = new (provider.get('Session'))();
      }

      this.oidc.session.acrValue = result.login.acr;
      this.oidc.session.account = result.login.account;
      this.oidc.session.loginTs = result.login.ts;
    }

    this.oidc.result = result;

    yield next;
  };
};
