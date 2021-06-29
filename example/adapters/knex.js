/*
 * Tests, pakcage.json and usage examples can be found here :
 * https://github.com/ydarma/oidc-provider-knex-adapter
 * This code is provided under "The Unlicense"
 */

const knex = require("knex");
const oidc_payloads = "oidc_payloads";

const types = [
  "Session",
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "ClientCredentials",
  "Client",
  "InitialAccessToken",
  "RegistrationAccessToken",
  "Interaction",
  "ReplayDetection",
  "PushedAuthorizationRequest",
  "Grant",
].reduce((map, name, i) => ({ ...map, [name]: i + 1 }), {});

function knexAdapter(client, cleanInterval = 3600000) {

  let _client = undefined;
  let _lastCleaned = Date.now();

  function getClient() {
    if (typeof _client == "undefined")
      _client = typeof client == "function" ? client : knex(client);
    return _client;
  }

  function shouldClean() {
    return Date.now() > _lastCleaned + cleanInterval;
  }

  function clean() {
    return getClient()
      .table(oidc_payloads)
      .where("expiresAt", "<", new Date())
      .delete().then(() => {
        _cleaned = Date.now();
      });
  }

  function getExpireAt(expiresIn) {
    return expiresIn
      ? new Date(Date.now() + expiresIn * 1000)
      : undefined;
  }

  return class DbAdapter {
    constructor(name) {
      this.name = name;
      this.type = types[name];
      if (shouldClean()) DbAdapter._cleaned = clean();
    }

    async upsert(id, payload, expiresIn) {
      const expiresAt = getExpireAt(expiresIn);
      await getClient()
        .table(oidc_payloads)
        .insert({
          id,
          type: this.type,
          payload: JSON.stringify(payload),
          grantId: payload.grantId,
          userCode: payload.userCode,
          uid: payload.uid,
          expiresAt,
        })
        .onConflict(["id", "type"])
        .merge();
    }

    get _table() {
      return getClient()
        .table(oidc_payloads)
        .where("type", this.type);
    }

    _rows(obj) {
      return this._table.where(obj);
    }

    _result(r) {
      return r.length > 0
        ? {
          ...JSON.parse(r[0].payload),
          ...(r[0].consumedAt ? { consumed: true } : undefined),
        }
        : undefined;
    }

    _findBy(obj) {
      return this._rows(obj).then(this._result);
    }

    find(id) {
      return this._findBy({ id });
    }

    findByUserCode(userCode) {
      return this._findBy({ userCode });
    }

    findByUid(uid) {
      return this._findBy({ uid });
    }

    destroy(id) {
      return this._rows({ id }).delete();
    }

    revokeByGrantId(grantId) {
      return this._rows({ grantId }).delete();
    }

    consume(id) {
      return this._rows({ id }).update({ consumedAt: new Date() });
    }
  };
}

const defaultConfig = {
  client: "pg",
  connection: "postgresql://"
};

const defaultAdapter = knexAdapter(defaultConfig)
defaultAdapter.knexAdapter = knexAdapter

module.exports = defaultAdapter
