'use strict';

const EventEmitter = require('events').EventEmitter;
const Mongo = require('mongodb').MongoClient; // eslint-disable-line import/no-unresolved
const _ = require('lodash');

const emitter = new EventEmitter();
let DB;
let connecting = Mongo.connect(process.env.MONGODB_URI).then((db) => {
  DB = db;
  connecting = undefined;
  emitter.emit('ready');
});

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
    collections.add(this.name);
  }

  coll(name) {
    return this.constructor.coll(name || this.name);
  }

  static coll(name) {
    if (connecting) return Promise.reject(new Error('DB connection not established'));
    return DB.collection(name);
  }

  destroy(id) {
    return this.coll().findOneAndDelete({ _id: id })
      .then((found) => {
        if (found.value && found.value.grantId) {
          const promises = [];

          collections.forEach((name) => {
            promises.push(this.coll(name).deleteMany({ grantId: found.value.grantId }));
          });

          return Promise.all(promises);
        }
        return undefined;
      });
  }

  consume(id) {
    return this.coll().findOneAndUpdate({ _id: id }, { $currentDate: { consumed: true } });
  }

  find(id) {
    return this.coll().find({ _id: id }).limit(1).next();
  }

  upsert(_id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + (expiresIn * 1000));
    }

    const document = Object.assign(payload, expiresAt && { expiresAt });
    
    return this.coll().updateOne({ _id }, document, { upsert: true });
  }
}

MongoAdapter.once = function onceReady() {
  emitter.once.apply(emitter, arguments);
};

MongoAdapter.on = function onReady() {
  emitter.on.apply(emitter, arguments);
};

module.exports = MongoAdapter;
