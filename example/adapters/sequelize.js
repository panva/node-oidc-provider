/*
 * This is a very rough-edged example, the idea is to still work with the fact that oidc-provider
 * has a rather "dynamic" schema. This example uses sequelize with sqlite, and all dynamic data
 * uses JSON fields. id is set to be the primary key, grantId should be additionaly indexed for
 * models where these fields are set.
*/

const Sequelize = require('sequelize'); // eslint-disable-line import/no-unresolved

const sequelize = new Sequelize('database', 'username', 'password', {
  dialect: 'sqlite',
  storage: 'db.sqlite',
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
    grantId: { type: Sequelize.UUIDV4 },
    userCode: { type: Sequelize.UUIDV4 },
    data: { type: Sequelize.JSON },
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
    try {
      await this.model.upsert({
        id,
        data,
        ...(data.grantId ? { grantId: data.grantId } : undefined),
        ...(data.userCode ? { userCode: data.userCode } : undefined),
        ...(expiresIn ? { expiresAt: new Date(Date.now() + (expiresIn * 1000)) } : undefined),
      });
    } catch (error) {
      throw error
    }
  }

  async find(id) {
    try {
      const found = await this.model.findByPk(id);
      if (!found) return undefined;
      return {
        ...found.data,
        ...(found.consumedAt ? { consumed: true } : undefined),
      };      
    } catch (error) {
      throw error
    }
  }

  async findByUserCode(userCode) {
    try {
      const found = await this.model.findOne({ where: { userCode } });
      if (!found) return undefined;
      return {
        ...found.data,
        ...(found.consumedAt ? { consumed: true } : undefined),
      };  
    } catch (error) {
      throw error
    }
  }

  async destroy(id) {
    try {
      await this.model.destroy({ where: { id } });
    } catch (error) {
      throw error
    }    
  }

  async consume(id) {
    try {
      await this.model.update({ consumedAt: new Date() }, { where: { id } });
    } catch (error) {
      throw error
    }
  }

  //  AccessToken, RefreshToken, AuthorizationCode & DeviceCode adapter instances expect to have
  //  `revokeByGrantId` method which accepts a string parameter `grantId` and revokes all tokens
  //  with its matching value in the `grantId` property
  async revokeByGrantId(grantId) {
    try {
      await this.model.destroy({ where: { grantId } });
    } catch (error) {
      throw error;
    }
  }

  static async connect() {
    return sequelize.sync();
  }
}

module.exports = SequelizeAdapter;
