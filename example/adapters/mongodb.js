const { MongoClient } = require('mongodb'); // eslint-disable-line import/no-unresolved
const { snakeCase } = require('lodash');

let DB;

const grantable = new Set([
  'access_token',
  'authorization_code',
  'refresh_token',
  'device_code',
]);

function cleanupReturn(res) {
  if (res) {
    delete res._id; // eslint-disable-line no-underscore-dangle
    delete res.expiresAt;
  }

  return res;
}

class CollectionSet extends Set {
  add(name) {
    const nu = this.has(name);
    super.add(name);
    if (!nu) {
      DB.collection(name).createIndexes([
        ...(grantable.has(name)
          ? [{
            key: { grantId: 1 },
            partialFilterExpression: { grantId: { $exists: true } },
            background: true,
          }] : []),
        ...(name === 'device_code'
          ? [{
            key: { userCode: 1 },
            partialFilterExpression: { userCode: { $exists: true } },
            background: true,
            unique: true,
          }] : []),
        {
          key: { expiresAt: 1 },
          expireAfterSeconds: 0,
          background: true,
        },
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

  // note: the payload for Session model may contain client_id as keys, make sure you do not use
  //   dots (".") in your client_id value charset.
  async upsert(_id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + (expiresIn * 1000));
    }

    const unset = Object.entries(payload).reduce((acc, [key, value]) => {
      if (value === undefined) {
        acc[key] = '';
        delete payload[key]; // eslint-disable-line no-param-reassign
      }
      return acc;
    }, {});

    await this.coll().updateOne({ _id }, {
      $set: {
        _id,
        ...payload,
        ...(expiresAt ? { expiresAt } : undefined),
      },
      ...(Object.keys(unset).length ? { $unset: unset } : undefined),
    }, { upsert: true });
  }

  async find(_id) {
    return this.coll().find({ _id }).limit(1).next()
      .then(cleanupReturn);
  }

  async findByUserCode(userCode) {
    return this.coll().find({ userCode }).limit(1).next()
      .then(cleanupReturn);
  }

  async destroy(_id) {
    const found = await this.coll().findOneAndDelete({ _id });
    if (found.value && found.value.grantId) {
      const promises = [];

      collections.forEach((name) => {
        if (grantable.has(name)) {
          promises.push(this.coll(name).deleteMany({ grantId: found.value.grantId }));
        }
      });

      await Promise.all(promises);
    }
  }

  async consume(_id) {
    await this.coll().findOneAndUpdate({ _id }, { $currentDate: { consumed: true } });
  }

  coll(name) {
    return this.constructor.coll(name || this.name);
  }

  static coll(name) {
    return DB.collection(name);
  }

  static async connect() {
    const connection = await MongoClient.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
    });
    DB = connection.db(connection.s.options.dbName);
  }
}

module.exports = MongoAdapter;
