'use strict';

const Mongo = require('mongodb').MongoClient; // eslint-disable-line import/no-unresolved
const _ = require('lodash');

let DB;
let connecting;

class CollectionSet extends Set {
  add(name) {
    const nu = this.has.apply(this, arguments);
    super.add.apply(this, arguments);
    if (!nu) {
      DB.collection(name).createIndexes([
        { key: { grantId: 1 } },
        { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
      ]).catch(console.error); // eslint-disable-line no-console
    }
  }
}

const collections = new CollectionSet();

class MongoAdapter {
  constructor(name) {
    this.name = _.snakeCase(name);
  }

  coll(name) {
    return this.constructor.coll(name || this.name);
  }

  static coll(name) {
    if (DB) return Promise.resolve(DB.collection(name));
    if (connecting) return Promise.reject(new Error('mongodb connection not established yet'));
    connecting = true;
    return Mongo.connect('mongodb://localhost/test').then((db) => {
      if (DB) {
        db.close(true); // a race condition resulted in more connections, close this one
      } else {
        connecting = false;
        DB = db;
        collections.add(name);
      }
      return DB.collection(name);
    });
  }

  destroy(id) {
    return this.coll()
      .then((coll) => coll.findOneAndDelete({ _id: id }))
      .then((found) => {
        if (found.lastErrorObject.n && found.value.grantId) {
          const promises = [];
          collections.forEach((name) => {
            promises.push(this.coll(name)
              .then((coll) => coll.findOneAndDelete({ grantId: found.value.grantId })));
          });
          return Promise.all(promises);
        }
        return undefined;
      });
  }

  consume(id) {
    return this.coll().then((coll) => coll.findOneAndUpdate({ _id: id },
      { $set: { consumed: new Date() } }));
  }

  find(id) {
    return this.coll().then((coll) => coll.find({ _id: id }).limit(1).next());
  }

  upsert(_id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      const now = new Date();
      expiresAt = new Date((now.getTime() + expiresIn) * 1000);
    }

    const document = Object.assign({ _id }, payload, { expiresAt });
    return this.coll().then((coll) => coll.insertOne(document));
  }
}

module.exports = MongoAdapter;
