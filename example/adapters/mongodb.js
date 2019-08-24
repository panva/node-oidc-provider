/* eslint-disable max-classes-per-file */

// npm i mongodb@^3.0.0
const { MongoClient } = require('mongodb'); // eslint-disable-line import/no-unresolved
const snakeCase = require('lodash/snakeCase');

let DB;

const grantable = new Set([
  'access_token',
  'authorization_code',
  'refresh_token',
  'device_code',
]);

class CollectionSet extends Set {
  add(name) {
    const nu = this.has(name);
    super.add(name);
    if (!nu) {
      DB.collection(name).createIndexes([
        ...(grantable.has(name)
          ? [{
            key: { 'payload.grantId': 1 },
          }] : []),
        ...(name === 'device_code'
          ? [{
            key: { 'payload.userCode': 1 },
            unique: true,
          }] : []),
        ...(name === 'session'
          ? [{
            key: { 'payload.uid': 1 },
            unique: true,
          }] : []),
        {
          key: { expiresAt: 1 },
          expireAfterSeconds: 0,
        },
      ]).catch(console.error); // eslint-disable-line no-console
    }
  }
}

const collections = new CollectionSet();

class MongoAdapter {
  constructor(name) {
    this.name = snakeCase(name);

    // NOTE: you should never be creating indexes at runtime in production, the following is in
    //   place just for demonstration purposes of the indexes required
    collections.add(this.name);
  }

  // NOTE: the payload for Session model may contain client_id as keys, make sure you do not use
  //   dots (".") in your client_id value charset.
  async upsert(_id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + (expiresIn * 1000));
    }

    await this.coll().updateOne(
      { _id },
      { $set: { payload, ...(expiresAt ? { expiresAt } : undefined) } },
      { upsert: true },
    );
  }

  async find(_id) {
    const result = await this.coll().find(
      { _id },
      { payload: 1 },
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async findByUserCode(userCode) {
    const result = await this.coll().find(
      { 'payload.userCode': userCode },
      { payload: 1 },
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async findByUid(uid) {
    const result = await this.coll().find(
      { 'payload.uid': uid },
      { payload: 1 },
    ).limit(1).next();

    if (!result) return undefined;
    return result.payload;
  }

  async destroy(_id) {
    await this.coll().deleteOne({ _id });
  }

  async revokeByGrantId(grantId) {
    await this.coll().deleteMany({ 'payload.grantId': grantId });
  }

  async consume(_id) {
    await this.coll().findOneAndUpdate(
      { _id },
      { $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } },
    );
  }

  coll(name) {
    return this.constructor.coll(name || this.name);
  }

  static coll(name) {
    return DB.collection(name);
  }

  // This is not part of the required or supported API, all initialization should happen before
  // you pass the adapter to `new Provider`
  static async connect() {
    const connection = await MongoClient.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
    });
    DB = connection.db(connection.s.options.dbName);
  }
}

module.exports = MongoAdapter;
