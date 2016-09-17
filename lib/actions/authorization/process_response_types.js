'use strict';

const _ = require('lodash');
const errors = require('../../helpers/errors');

module.exports = (provider) => {
  const AccessToken = provider.AccessToken;
  const AuthorizationCode = provider.AuthorizationCode;
  const IdToken = provider.IdToken;

  function* tokenHandler() {
    const at = new AccessToken({
      accountId: this.oidc.session.accountId(),
      claims: this.oidc.claims,
      clientId: this.oidc.client.clientId,
      grantId: this.oidc.uuid,
      scope: this.oidc.params.scope,
    });

    return {
      access_token: yield at.save(),
      expires_in: AccessToken.expiresIn,
      token_type: 'Bearer',
    };
  }

  function* codeHandler() {
    const ac = new AuthorizationCode({
      accountId: this.oidc.session.accountId(),
      acr: this.oidc.session.acr(this.oidc.uuid),
      authTime: this.oidc.session.authTime(),
      claims: this.oidc.claims,
      clientId: this.oidc.client.clientId,
      codeChallenge: this.oidc.params.code_challenge,
      codeChallengeMethod: this.oidc.params.code_challenge_method,
      grantId: this.oidc.uuid,
      nonce: this.oidc.params.nonce,
      redirectUri: this.oidc.params.redirect_uri,
      scope: this.oidc.params.scope,
    });

    if (provider.configuration('features.backchannelLogout')) {
      ac.sid = this.oidc.session.sidFor(this.oidc.client.clientId);
    }

    return { code: yield ac.save() };
  }

  function idTokenHandler() {
    const token = new IdToken(
      Object.assign({}, this.oidc.account.claims(), {
        acr: this.oidc.session.acr(this.oidc.uuid),
        auth_time: this.oidc.session.authTime(),
      }), this.oidc.client.sectorIdentifier);

    token.scope = this.oidc.params.scope;
    token.mask = _.get(this.oidc.claims, 'id_token', {});

    token.set('nonce', this.oidc.params.nonce);

    if (provider.configuration('features.backchannelLogout')) {
      token.set('sid', this.oidc.session.sidFor(this.oidc.client.clientId));
    }

    return { id_token: token };
  }

  function noneHandler() {
    return {};
  }

  function callHandlers(responseType) {
    let fn;
    switch (responseType) {
      case 'none':
        fn = noneHandler.apply(this);
        break;
      case 'token':
        fn = tokenHandler.apply(this);
        break;
      case 'id_token':
        fn = idTokenHandler.apply(this);
        break;
      case 'code':
        fn = codeHandler.apply(this);
        break;
      /* istanbul ignore next */
      default:
        throw new errors.InvalidRequestError('not implemented', 501);
    }

    return fn;
  }

  /*
   * Resolves each requested response type to a single response object. If one of the hybrid
   * response types is used an appropriate _hash is also pushed on to the id_token.
   */
  return function* processResponseTypes() {
    const responses = this.oidc.params.response_type.split(' ');
    const out = Object.assign.apply({}, yield responses.map(callHandlers.bind(this)));

    if (out.access_token && out.id_token) {
      out.id_token.set('at_hash', out.access_token);
    }

    if (out.code && out.id_token) {
      out.id_token.set('c_hash', out.code);
    }

    if (out.id_token) {
      out.id_token = yield out.id_token.sign(this.oidc.client);
    }

    return out;
  };
};
