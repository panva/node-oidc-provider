/*
 * This is a very rough-edged example, the idea is to still work with the fact that oidc-provider
 * has a rather "dynamic" schema. This example uses sequelize with postgresql, and all dynamic data
 * uses JSON fields. id is set to be the primary key, grantId should be additionaly indexed for
 * models where these fields are set (grantId-able models). userCode should be additionaly indexed
 * for DeviceCode model. uid should be additionaly indexed for Session model. For sequelize
 * migrations @see https://github.com/Rogger794/node-oidc-provider/tree/examples/example/migrations/sequelize
*/

// npm i sequelize@^5.21.2
const Sequelize = require('sequelize'); // eslint-disable-line import/no-unresolved

const sequelize = new Sequelize('databaseName', 'username', 'password', {
  host: 'databaseHost',
  dialect: 'postgres',
});

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
]);

const models = [
  'Session',
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'ClientCredentials',
  'Client',
  'InitialAccessToken',
  'RegistrationAccessToken',
  'Interaction',
  'ReplayDetection',
  'PushedAuthorizationRequest',
].reduce((map, name) => {
  map.set(name, sequelize.define(name, {
    id: { type: Sequelize.STRING, primaryKey: true },
    ...(grantable.has(name) ? { grantId: { type: Sequelize.STRING } } : undefined),
    ...(name === 'DeviceCode' ? { userCode: { type: Sequelize.STRING } } : undefined),
    ...(name === 'Session' ? { uid: { type: Sequelize.STRING } } : undefined),
    data: { type: Sequelize.JSONB },
    expiresAt: { type: Sequelize.DATE },
    consumedAt: { type: Sequelize.DATE },
  }));

  return map;
}, new Map());

class SequelizeAdapter {
  constructor(name) {
    this.model = models.get(name);
    this.name = name;
  }

  async upsert(id, data, expiresIn) {
    await this.model.upsert({
      id,
      data,
      ...(data.grantId ? { grantId: data.grantId } : undefined),
      ...(data.userCode ? { userCode: data.userCode } : undefined),
      ...(data.uid ? { uid: data.uid } : undefined),
      ...(expiresIn ? { expiresAt: new Date(Date.now() + (expiresIn * 1000)) } : undefined),
    });
  }

  async find(id) {
    const found = await this.model.findByPk(id);
    if (!found) return undefined;
    return {
      ...found.data,
      ...(found.consumedAt ? { consumed: true } : undefined),
    };
  }

  async findByUserCode(userCode) {
    const found = await this.model.findOne({ where: { userCode } });
    if (!found) return undefined;
    return {
      ...found.data,
      ...(found.consumedAt ? { consumed: true } : undefined),
    };
  }

  async findByUid(uid) {
    const found = await this.model.findOne({ where: { uid } });
    if (!found) return undefined;
    return {
      ...found.data,
      ...(found.consumedAt ? { consumed: true } : undefined),
    };
  }

  async destroy(id) {
    await this.model.destroy({ where: { id } });
  }

  async consume(id) {
    await this.model.update({ consumedAt: new Date() }, { where: { id } });
  }

  async revokeByGrantId(grantId) {
    await this.model.destroy({ where: { grantId } });
  }

  static async connect() {
    return sequelize.sync();
  }
}

module.exports = SequelizeAdapter;
