// Author: Marc-Aurèle Darche @madarche
// For questions/suggestions/fixes related to this adapter create an
// issue in this dedicated repository: https://github.com/madarche/contact

/* eslint-disable class-methods-use-this */

// This is the SQL used to create the schema in PostgreSQL:
//
// CREATE TABLE record
// (
//   id text PRIMARY KEY,
//   grantId text,
//   data jsonb,
//   created_at TIMESTAMP NOT NULL DEFAULT localtimestamp,
//   updated_at TIMESTAMP NOT NULL DEFAULT localtimestamp,
//   expires_at TIMESTAMP
// );

const knexCreate = require('knex'); // eslint-disable-line import/no-unresolved
const bookshelfCreate = require('bookshelf'); // eslint-disable-line import/no-unresolved

const knex = knexCreate({
  client: 'postgres',
  connection: {
    host: 'host',
    port: 'port',
    database: 'database',
    user: 'user',
    password: 'password',
    charset: 'utf8',
  },
});
const bookshelf = bookshelfCreate(knex);

const Record = bookshelf.Model.extend({
  tableName: 'record',
  hasTimestamps: true,
});

function getEpochTime() {
  return Math.floor(Date.now() / 1000);
}

class BookshelfPostgresqlAdapter {
  /**
   * Creates an instance of MyAdapter for an oidc-provider model.
   *
   * @constructor
   * @param {string} name Name of the oidc-provider model. One of "Session", "AccessToken",
   * "AuthorizationCode", "RefreshToken", "ClientCredentials" or "Client", "InitialAccessToken",
   * "RegistrationAccessToken"
   */
  constructor(name) {
    this.name = name;
  }

  /**
   * Updates or Creates an instance of an oidc-provider model.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier that oidc-provider will use to reference
   * this model instance for future operations.
   * @param {object} payload Object with all properties intended for storage.
   * @param {expiresIn} integer Number of seconds intended for this model to be stored.
   */
  async upsert(id, payload, expiresIn) {
    const updateData = {
      data: payload,
    };

    if (expiresIn) {
      updateData.expires_at = new Date(Date.now() + (expiresIn * 1000));
    }

    let record = await new Record({ id }).fetch();
    if (record) {
      await record.set(updateData).save();
    } else {
      updateData.id = id;
      record = await new Record().save(updateData);
    }

    const { grantId } = payload;
    if (grantId) {
      const grant = await new Record()
        .where('id', grantId)
        .fetch();

      const ids = grant ? grant.get('data') : [];
      ids.push(id);

      // Note that when setting an array (or a value that could be an
      // array) as the value of a json or jsonb column, you should use
      // JSON.stringify() to convert your value to a string prior to
      // passing it to the query builder.
      // This is because postgresql has a native array type which uses a
      // syntax incompatible with json; knex has no way of knowing which
      // syntax to use, and calling JSON.stringify() forces json-style
      // syntax.
      // cf. http://knexjs.org/#Schema-json
      const data = JSON.stringify(ids);

      if (grant) {
        await grant.set({ data }).save();
      } else {
        await new Record().save({ id: grantId, data });
      }
    }
  }

  /**
     * Returns previously stored instance of an oidc-provider model.
     *
     * @return {Promise} Promise fulfilled with either Object (when found and not dropped yet due to
     *     expiration) or falsy value when not found anymore. Rejected with error when encountered.
     * @param {string} id Identifier of oidc-provider model
     */
  async find(id) {
    return new Record()
      .where('id', id)
      .fetch()
      .then((record) => {
        if (!record) {
          return null;
        }

        // Deleting the record if expired
        if (new Date(record.expires_at) >= Date.now()) {
          return record.destroy()
            .then(() => null);
        }

        return record.get('data');
      });
  }

  /**
   * Marks a stored oidc-provider model as consumed (not yet expired
   * though!). Future finds for this id should be fulfilled with an object
   * containing additional property named "consumed".
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   *     encountered.
   * @param {string} id Identifier of oidc-provider model
   */
  async consume(id) {
    const record = await new Record()
      .where('id', id)
      .fetch();
    const data = record.get('data');
    data.consumed = getEpochTime();
    await record.save({ data }, { method: 'update', patch: true });
  }

  /**
   * Destroys/Drops/Removes a stored oidc-provider model and other grant
   * related models. Future finds for this id should be fulfilled with falsy
   * values.
   *
   * @return {Promise} Promise fulfilled when the operation
   *     succeeded. Rejected with error when encountered.
   * @param {string} id Identifier of oidc-provider model
   */
  async destroy(id) {
    const record = await new Record()
      .where('id', id)
      .fetch();
    const grantId = record && record.get('data').grantId;

    if (record) {
      await record.destroy();
    }

    if (grantId) {
      const tokens = await new Record()
        .where('id', grantId)
        .fetchAll();
      await tokens.invokeThen('destroy');
    }
  }

  /**
   * A one time hook called when initializing the Provider instance, use to establish necessary
   * connections if applicable, afterwards only new instances will initialized.
   *
   * @return {Promise} Promise fulfilled when the operation
   *     succeeded. Rejected with error when encountered.
   * @param {Provider} provider Provider instance for which the connection is needed
   */
  static connect(provider) { // eslint-disable-line no-unused-vars
  }
}

module.exports = BookshelfPostgresqlAdapter;
