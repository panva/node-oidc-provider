'use strict';

const uuid = require('uuid').v4;
const _ = require('lodash');
const epochTime = require('../helpers/epoch_time');

module.exports = function getSession(provider) {
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (provider.configuration('adapter'))('Session');
    return adapter;
  }

  class Session {
    constructor(id, data) {
      if (data) Object.assign(this, data);
      this.id = id;
    }

    accountId() {
      return this.account;
    }

    authTime() {
      return this.loginTs;
    }

    acr() {
      const conf = provider.configuration();
      if (epochTime() - this.authTime() < conf.ttl.acr) {
        return _.get(this, 'acrValue', conf.acrValues[0]);
      }

      return conf.acrValues[0];
    }

    past(age) {
      const maxAge = +age;

      if (this.loginTs && _.isFinite(maxAge) && maxAge > 0) {
        return epochTime() - this.loginTs >= maxAge;
      }

      return false;
    }

    save() {
      const payload = Object.assign({}, this);
      delete payload.id;

      return getAdapter().upsert(this.id, payload,
        provider.configuration('cookies.long.maxAge') / 1000);
    }

    destroy() {
      return getAdapter().destroy(this.id);
    }

    sidFor(clientId, value) {
      this.authorizations = this.authorizations || {};
      const key = String(clientId);
      if (value) {
        if (!this.authorizations[key]) this.authorizations[key] = {};
        this.authorizations[key].sid = value;
        return undefined;
      }

      return this.authorizations[key] && this.authorizations[key].sid;
    }

    static find(id) {
      return getAdapter().find(id).then(data => new Session(id, data));
    }

    static get(ctx) {
      // is there supposed to be a session bound? generate if not
      const sessionId = ctx.cookies.get('_session', {
        signed: provider.configuration('cookies.long.signed'),
      }) || uuid();

      return this.find(sessionId).then((session) => {
        // refresh the session duration
        ctx.cookies.set('_session', sessionId, provider.configuration('cookies.long'));
        return session;
      });
    }
  }

  return Session;
};
