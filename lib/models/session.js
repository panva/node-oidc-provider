'use strict';

let uuid = require('node-uuid');
let _ = require('lodash');

module.exports = function(provider) {
  class Session {
    constructor(id, data) {
      Object.assign(this, data);
      this.id = id;
    }

    static get adapter() {
      let conf = provider.configuration;
      if (!this._adapter) {
        this._adapter = new conf.adapters[conf.adapter](this.name);
      }

      return this._adapter;
    }

    get adapter() {
      return this.constructor.adapter;
    }

    accountId() {
      return this.account;
    }

    authTime() {
      return this.loginTs;
    }

    acr() {
      let conf = provider.configuration;
      if ((Date.now() / 1000 | 0) - this.authTime() < conf.ttl.acr) {
        return _.get(this, 'acrValue', conf.acrValuesSupported[0]);
      }

      return conf.acrValuesSupported[0];
    }

    past(maxAge) {
      maxAge = +maxAge;

      if (this.loginTs && _.isFinite(maxAge) && maxAge > 0) {
        return (Date.now() / 1000 | 0) - this.loginTs >= maxAge;
      }
      return false;
    }

    save() {
      if (this.id) {
        return this.adapter.upsert(this.id, Object.assign({}, this),
          provider.configuration.cookies.long.maxAge / 1000);
      }

      return Promise.resolve();
    }

    destroy() {
      return this.adapter.destroy(this.id);
    }

    static find(id) {
      return this.adapter.find(id)
        .then((data) => data ? new Session(id, data) : new Session(id));
    }

    static * get(ctx) {
      // is there supposed to be a session bound? generate if not
      let sessionId = ctx.cookies.get('_session', {
        signed: provider.configuration.cookies.long.signed,
      }) || uuid.v4();

      let session = yield this.find(sessionId); // jshint ignore:line

      // refresh the session duration
      ctx.cookies.set('_session', sessionId,
        provider.configuration.cookies.long);

      return session;
    }
  }

  return Session;
};
