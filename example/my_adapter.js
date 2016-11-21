/* eslint-disable */
'use strict';

class MyAdapter {

  /**
   *
   * Creates an instance of MyAdapter for an oidc-provider model.
   *
   * @constructor
   * @param {string} name Name of the oidc-provider model. One of "Session", "AccessToken",
   * "AuthorizationCode", "RefreshToken", "ClientCredentials" or "Client", "InitialAccessToken",
   * "RegistrationAccessToken"
   *
   */
  constructor(name) {

  }

  /**
   *
   * Update or Create an instance of an oidc-provider model.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier that oidc-provider will use to reference this model instance for
   * future operations.
   * @param {object} payload Object with all properties intended for storage.
   * @param {expiresIn} integer Number of seconds intended for this model to be stored.
   *
   */
  upsert(id, payload, expiresIn) {

    /**
     *
     * When this is one of AccessToken, AuthorizationCode, RefreshToken, ClientCredentials,
     * InitialAccessToken or RegistrationAccessToken the payload will contain the following
     * properties:
     * - grantId {string} the original id assigned to a grant (authorization request)
     * - header {string} oidc-provider tokens are themselves JWTs, this is the header part of the token
     * - payload {string} second part of the token
     * - signature {string} the signature of the token
     *
     * Hint: you can JSON.parse(base64decode( ... )) the header and payload to get the token
     * properties and store them too, they may be helpful for getting insights on your usage.
     * Modifying any of header, payload or signature values will result in the token being invalid,
     * remember that oidc-provider will do a JWT signature check of both the received and stored
     * token to detect potential manipulation.
     *
     * Hint2: in order to fulfill all OAuth2.0 behaviors in regards to invalidating and expiring
     * potentially misused or sniffed tokens you should keep track of all tokens that belong to the
     * same grantId.
     *
     * Client model will only use this when registered through Dynamic Registration features.
     *
     * Session model payload contains the following properties:
     * - account {string} the session account identifier
     * - authorizations {object} object with session authorized clients and their session identifiers
     * - loginTs {number} timestamp of user's authentication
     *
     */
  }

  /**
   *
   * Return previously stored instance of an oidc-provider model.
   *
   * @return {Promise} Promise fulfilled with either Object (when found and not dropped yet due to
   * expiration) or falsy value when not found anymore. Rejected with error when encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  find(id) {

  }

  /**
   *
   * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
   * id should be fulfilled with an object containing additional property named "consumed".
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  consume(id) {

  }

  /**
   *
   * Destroy/Drop/Remove a stored oidc-provider model and other grant related models. Future finds
   * for this id should be fulfilled with falsy values.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  destroy(id) {

    /**
     *
     * See upsert for the note on grantId, it's imperitive to destroy all tokens with the same
     * grantId when destroy is called. To query your persistancy store for the grantId of this token
     * and also trigger a chain of removals for all related tokens is recommended.
     *
     */
  }
}

module.exports = MyAdapter;
