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

const grantable = [
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
];

const models = [
  'Session',
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'ClientCredentials',
  'Client',
  'InitialAccessToken',
  'RegistrationAccessToken',
].reduce((map, name) => {
  map.set(name, sequelize.define(name, {
    id: { type: Sequelize.STRING, primaryKey: true },
    grantId: { type: Sequelize.UUIDV4 },
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
    return this.model.upsert({
      id,
      data,
      ...(data.grantId ? { grantId: data.grantId } : undefined),
      ...(expiresIn ? { expiresAt: new Date(Date.now() + (expiresIn * 1000)) } : undefined),
    });
  }

  async find(id) {
    return this.model.findByPrimary(id).then((found) => {
      if (!found) return undefined;
      return {
        ...found.data,
        ...(found.consumedAt ? { consumed: true } : undefined),
      };
    });
  }

  async destroy(id) {
    if (grantable.includes(this.name)) {
      return this.model.findByPrimary(id).then((({ grantId }) => (
        Promise.all(grantable.map(name => models.get(name).destroy({ where: { grantId } })))
      )));
    }

    return this.model.destroy({ where: { id } });
  }

  async consume(id) {
    return this.model.update({ consumedAt: new Date() }, { where: { id } });
  }

  static async connect() {
    return sequelize.sync();
  }
}

module.exports = SequelizeAdapter;
