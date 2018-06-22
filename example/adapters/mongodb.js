const { MongoClient } = require('mongodb'); // eslint-disable-line import/no-unresolved
const { snakeCase } = require('lodash');

let DB;

const grantable = [
  'access_token',
  'authorization_code',
  'refresh_token',
];

class CollectionSet extends Set {
  add(name) {
    const nu = this.has(name);
    super.add(name);
    if (!nu) {
      DB.collection(name).createIndexes([
        ...(grantable.includes(name)
          ? [{
            key: { grantId: 1 },
            partialFilterExpression: { grantId: { $exists: true } },
          }] : []),
        { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
      ]).catch(console.error); // eslint-disable-line no-console
    }
  }
}

const collections = new CollectionSet();

class MongoAdapter {
  constructor(name) {
    this.name = snakeCase(name);
    collections.add(this.name);
  }

  upsert(_id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + (expiresIn * 1000));
    }

    // HEROKU EXAMPLE ONLY, do not use the following block unless you want to drop dynamic
    //   registrations 24 hours after registration
    if (this.name === 'client') {
      expiresAt = new Date(Date.now() + (24 * 60 * 60 * 1000));
    }

    return this.coll().updateOne({ _id }, {
      $set: {
        _id,
        ...payload,
        ...(expiresAt ? { expiresAt } : undefined),
      },
    }, { upsert: true });
  }

  find(_id) {
    return this.coll().find({ _id }).limit(1).next();
  }

  destroy(_id) {
    return this.coll().findOneAndDelete({ _id })
      .then((found) => {
        if (found.value && found.value.grantId) {
          const promises = [];

          collections.forEach((name) => {
            if (grantable.includes(name)) {
              promises.push(this.coll(name).deleteMany({ grantId: found.value.grantId }));
            }
          });

          return Promise.all(promises);
        }
        return undefined;
      });
  }

  consume(_id) {
    return this.coll().findOneAndUpdate({ _id }, { $currentDate: { consumed: true } });
  }

  coll(name) {
    return this.constructor.coll(name || this.name);
  }

  static coll(name) {
    return DB.collection(name);
  }

  static async connect() {
    const connection = await MongoClient.connect(process.env.MONGODB_URI);
    DB = connection.db(connection.s.options.dbName);
  }
}

module.exports = MongoAdapter;
