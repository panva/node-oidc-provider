import instance from '../helpers/weak_cache.js';

import ctxRef from './ctx_ref.js';

export default function getBaseToken(provider) {
  class BaseToken extends instance(provider).BaseModel {
    #client;

    #resourceServer;

    constructor({
      client, resourceServer, expiresIn, ...rest
    } = {}) {
      super(rest);
      if (typeof client !== 'undefined') {
        this.client = client;
      }
      if (typeof resourceServer !== 'undefined') {
        this.resourceServer = resourceServer;
      }
      if (typeof expiresIn !== 'undefined') {
        this.expiresIn = expiresIn;
      }
    }

    set client(client) {
      this.clientId = client.clientId;
      this.#client = client;
    }

    get client() {
      return this.#client;
    }

    set resourceServer(resourceServer) {
      this.setAudience(resourceServer.audience || resourceServer.identifier());
      this.#resourceServer = resourceServer;
    }

    get resourceServer() {
      return this.#resourceServer;
    }

    static expiresIn(...args) {
      const ttl = instance(provider).configuration(`ttl.${this.name}`);

      if (typeof ttl === 'number') {
        return ttl;
      }

      if (typeof ttl === 'function') {
        return ttl(...args);
      }

      return undefined;
    }

    async save() {
      return super.save(this.remainingTTL);
    }

    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'clientId',
      ];
    }

    get expiration() {
      if (!this.expiresIn) {
        this.expiresIn = this.constructor.expiresIn(ctxRef.get(this), this, this.#client);
      }

      return this.expiresIn;
    }

    get scopes() {
      return new Set(this.scope && this.scope.split(' '));
    }

    get resourceIndicators() {
      return new Set(Array.isArray(this.resource) ? this.resource : [this.resource]);
    }
  }

  return BaseToken;
}
