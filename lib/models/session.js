'use strict';

const uuid = require('node-uuid');
const _ = require('lodash');

module.exports = function getSession(provider) {
  class Session {
    constructor(id, data) {
      if (data) Object.assign(this, data);
      this.id = id;
    }

    static get adapter() {
      const Adapter = provider.configuration('adapter');
      if (!this._adapter) {
        this._adapter = new Adapter(this.name);
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
      const conf = provider.configuration();
      if ((Date.now() / 1000 | 0) - this.authTime() < conf.ttl.acr) {
        return _.get(this, 'acrValue', conf.acrValues[0]);
      }

      return conf.acrValues[0];
    }

    past(age) {
      const maxAge = +age;

      if (this.loginTs && _.isFinite(maxAge) && maxAge > 0) {
        return (Date.now() / 1000 | 0) - this.loginTs >= maxAge;
      }
      return false;
    }

    save() {
      const payload = Object.assign({}, this);
      delete payload.id;

      if (this.id && !_.isEmpty(payload)) {
        return this.adapter.upsert(this.id, payload,
          provider.configuration('cookies.long.maxAge') / 1000);
      }

      return Promise.resolve();
    }

    destroy() {
      return this.adapter.destroy(this.id);
    }

    static find(id) {
      return this.adapter.find(id).then(data => new Session(id, data));
    }

    static get(ctx) {
      // is there supposed to be a session bound? generate if not
      const sessionId = ctx.cookies.get('_session', {
        signed: provider.configuration('cookies.long.signed'),
      }) || uuid.v4();

      return this.find(sessionId).then((session) => {
        // refresh the session duration
        ctx.cookies.set('_session', sessionId, provider.configuration('cookies.long'));
        return session;
      });
    }
  }

  return Session;
};
