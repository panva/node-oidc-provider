/**
 * @file Google Cloud Datastore adapter
 * For questions/suggestions/fixes related to this adapter create an
 * issue in this dedicated repository: https://github.com/cymarechal/node-oidc-provider
 *
 * @author Cyril Maréchal - @cymarechal
 * @requires NPM:@google-cloud/datastore
 */

const Datastore = require('@google-cloud/datastore');

let DB;

const grantable = [
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
];

class Adapter {
  constructor(name) {
    this.name = name;
  }

  async upsert(id, payload, expiresIn) {
    return DB.upsert({
      key: DB.key([this.name, id]),
      data: {
        id,
        ...payload,
        ...(expiresIn ? { expiresAt: new Date(Date.now() + (expiresIn * 1000)) } : undefined),
      },
    });
  }

  async find(id) {
    return DB.get(DB.key([this.name, id]))
      .then((data) => {
        const entity = data[0];
        if (entity && entity.expiresAt > Date.now()) {
          return entity;
        }

        return undefined;
      });
  }

  async consume(id) {
    const entity = await this.find(id);
    entity.consumed = true;

    return DB.update({
      key: DB.key([this.name, id]),
      data: entity,
    });
  }

  async destroy(id) {
    if (grantable.includes(this.name)) {
      await this.find(id).then(({ grantId }) => (
        Promise.all(grantable.map((name) => {
          const query = DB.createQuery(name).filter('grantId', '=', grantId);
          return query.run().then((data) => {
            const entities = data[0];

            return Promise.all(
              entities.map(
                entity => DB.delete(DB.key([name, entity.id])).catch(() => {}),
              ),
            );
          });
        }))
      ));
    }

    return DB.delete(DB.key([this.name, id]));
  }

  static async connect() {
    DB = new Datastore();
  }
}

module.exports = Adapter;
