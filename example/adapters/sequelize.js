/*
 * This is a very rough-edged example, the idea is to still work with the fact that oidc-provider
 * has a rather "dynamic" schema. This example uses sequelize with sqlite, and all dynamic data
 * uses JSON fields. id is set to be the primary key, grantId should be additionaly indexed for
 * models where these fields are set.
*/

const Sequelize = require('sequelize'); // eslint-disable-line import/no-unresolved

const sequelize = new Sequelize('databaseName', 'username', 'password', {
  host: 'databaseHost',
  dialect: 'postgres',
});

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
].reduce((map, name) => {
  map.set(name, sequelize.define(name, {
    id: { type: Sequelize.STRING, primaryKey: true },
    grantId: { type: Sequelize.STRING },
    userCode: { type: Sequelize.STRING },
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
      ...(found.consumedAt ? { consumedAt: Date.now() } : undefined),
    };
  }

  async findByUid(uid) {
    const found=await this.model.findOne({where: {data:{uid}}});
    if (!found) return undefined;
    return {
      ...found.data,
      ...(found.consumedAt ? { consumedAt: Date.now() } : undefined),
    };
  }

  async destroy(id) {
    await this.model.destroy({ where: { id } });    
  }

  async consume(id) {
    const found = await this.model.findByPk(id);
    if (!found)
      return undefined;
    await found.update({ consumedAt: new Date() });
    if (!found)
      return undefined;
    return {
      ...found.data,
      consumedAt: found.consumedAt,
    };
  }

  async revokeByGrantId(grantId) {
    await this.model.destroy({ where: { grantId } });
  }

  static async connect() {
    return sequelize.sync();
  }
}

module.exports = SequelizeAdapter;
