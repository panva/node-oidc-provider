/* eslint-disable */

/*
 * This is a very rough-edged example, the idea is to still work with the fact that oidc-provider
 * has a rather "dynamic" schema. This example uses sequelize with sqlite, and all dynamic data
 * uses JSON fields. uuid is set to be the primary key and grantId should be additionaly indexed
 * for token models.
*/

'use strict';

const Sequelize = require('sequelize');
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
    uuid: { type: Sequelize.STRING, primaryKey: true },
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

  async upsert(id, payload, expiresIn) {
    return this.model.upsert(Object.assign(
      {},
      { data: payload },
      { uuid: id },
      payload.grantId ? { grantId: payload.grantId } : undefined,
      expiresIn ? { expiresAt: new Date(Date.now() + (expiresIn * 1000)) } : undefined ));
  }

  async find(id) {
    return this.model.findByPrimary(id).then((found) => {
      if (found) {
        return found.consumedAt ? Object.assign({}, found.data, { consumed: true }) : found.data;
      }
      return undefined;
    });
  }

  async consume(id) {
    return this.model.update({ consumedAt: new Date() }, { where: { uuid: id }});
  }

  async destroy(id) {
    if (grantable.includes(this.name)) {
      return this.model.findByPrimary(id).then((({ grantId }) => {
        return Promise.all(grantable.map(name => models.get(name).destroy({ where: { grantId }})));
      }));
    }

    return this.model.destroy({ where: { uuid: id }});
  }

  static async connect(provider) {
    return sequelize.sync();
  }
}

module.exports = SequelizeAdapter;
