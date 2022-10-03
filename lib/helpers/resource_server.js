/* eslint-disable no-underscore-dangle */

module.exports = class ResourceServer {
  constructor(identifier, data) {
    this._identifier = identifier;
    this.audience = data.audience;
    this.scope = data.scope;
    this.accessTokenTTL = data.accessTokenTTL;
    this.accessTokenFormat = data.accessTokenFormat;
    this.jwt = data.jwt;
    this.paseto = data.paseto;
  }

  get scopes() {
    return new Set(this.scope && this.scope.split(' '));
  }

  identifier() {
    return this._identifier;
  }
};
