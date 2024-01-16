/* eslint-disable */
'use strict';

class MyAdapter {

  /**
   *
   * Creates an instance of MyAdapter for an oidc-provider model.
   *
   * @constructor
   * @param {string} name Name of the oidc-provider model. One of "Grant, "Session", "AccessToken",
   * "AuthorizationCode", "RefreshToken", "ClientCredentials", "Client", "InitialAccessToken",
   * "RegistrationAccessToken", "DeviceCode", "Interaction", "ReplayDetection",
   * "BackchannelAuthenticationRequest", or "PushedAuthorizationRequest"
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
   * @param {integer} expiresIn Number of seconds intended for this model to be stored.
   *
   */
  async upsert(id, payload, expiresIn) {

    /**
     *
     * When this is one of AccessToken, AuthorizationCode, RefreshToken, ClientCredentials,
     * InitialAccessToken, RegistrationAccessToken or DeviceCode the payload will contain the
     * following properties:
     *
     * Note: This list is not exhaustive and properties may be added in the future, it is highly
     * recommended to use a schema that allows for this.
     *
     * - jti {string} - unique identifier of the token
     * - kind {string} - token class name
     * - exp {number} - timestamp of the token's expiration
     * - iat {number} - timestamp of the token's creation
     * - accountId {string} - account identifier the token belongs to
     * - clientId {string} - client identifier the token belongs to
     * - aud {string} - audience of a token
     * - authTime {number} - timestamp of the end-user's authentication
     * - claims {object} - claims parameter (see claims in OIDC Core 1.0)
     * - extra {object} - extra claims returned by the extraTokenClaims helper
     * - codeChallenge {string} - client provided PKCE code_challenge value
     * - codeChallengeMethod {string} - client provided PKCE code_challenge_method value
     * - sessionUid {string} - uid of a session this token stems from
     * - expiresWithSession {boolean} - whether the token is valid when session expires
     * - grantId {string} - grant identifier
     * - nonce {string} - random nonce from an authorization request
     * - redirectUri {string} - redirect_uri value from an authorization request
     * - resource {string|string[]} - resource indicator value(s) (auth code, device code, refresh token)
     * - rotations {number} - [RefreshToken only] - number of times the refresh token was rotated
     * - iiat {number} - [RefreshToken only] - the very first (initial) issued at before rotations
     * - acr {string} - authentication context class reference value
     * - amr {string[]} - Authentication methods references
     * - scope {string} - scope value from an authorization request
     * - sid {string} - session identifier the token comes from
     * - 'x5t#S256' {string} - X.509 Certificate SHA-256 Thumbprint of a certificate bound access or
     *     refresh token
     * - 'jkt' {string} - JWK SHA-256 Thumbprint (according to [RFC7638]) of a DPoP bound
     *     access or refresh token
     * - gty {string} - [AccessToken, RefreshToken only] space delimited grant values, indicating
     *     the grant type(s) they originate from (implicit, authorization_code, refresh_token or
     *     device_code) the original one is always first, second is refresh_token if refreshed
     * - params {object} - [DeviceCode and BackchannelAuthenticationRequest only] an object with the
     *     authorization request parameters as requested by the client with device_authorization_endpoint
     * - userCode {string} - [DeviceCode only] user code value
     * - deviceInfo {object} - [DeviceCode only] an object with details about the
     *     device_authorization_endpoint request
     * - inFlight {boolean} - [DeviceCode only]
     * - error {string} - [DeviceCode and BackchannelAuthenticationRequest only] - error from authnz to be
     *     returned to the polling client
     * - errorDescription {string} - [DeviceCode and BackchannelAuthenticationRequest only] - error_description
     *     from authnz to be returned to the polling client
     * - policies {string[]} - [InitialAccessToken, RegistrationAccessToken only] array of policies
     * - request {string} - [PushedAuthorizationRequest only] Pushed Request Object value
     * - dpopJkt {string} - [PushedAuthorizationRequest only] Calculated or provided dpop_jkt parameter
     * - trusted {boolean} - [PushedAuthorizationRequest only] Whether the parameters in the PAR object
     *     were coming from an authenticated request or an authenticated source.
     *
     * Client model will only use this when registered through Dynamic Registration features and
     * will contain all client properties.
     *
     * Grant model payload contains the following properties:
     * - jti {string} - Grant's unique identifier
     * - kind {string} - "Grant" fixed string value
     * - exp {number} - timestamp of the grant's expiration. exp will be missing when expiration
     *     is not configured on the Grant model.
     * - iat {number} - timestamp of the grant's creation
     * - accountId {string} - the grant account identifier
     * - clientId {string} - client identifier the grant belongs to
     * - openid {object}
     * - openid.scope {string} - Granted OpenId Scope value
     * - openid.claims {string[]} - Granted OpenId Claim names
     * - resources {object}
     * - resources[resourceIndicator] {string} - Granted Scope value for a Resource Server
     *     (indicated by its resource indicator value)
     * - resources {object}
     * - rejected.openid {object}
     * - rejected.openid.scope {string} - Rejected OpenId Scope value
     * - rejected.openid.claims {string[]} - Rejected OpenId Claim names
     * - rejected.resources {object}
     * - rejected.resources[resourceIndicator] {string} - Rejected Scope value for a Resource Server
     *     (indicated by its resource indicator value)
     *
     * OIDC Session model payload contains the following properties:
     * - jti {string} - Session's unique identifier, it changes on some occasions
     * - uid {string} - Session's unique fixed internal identifier
     * - kind {string} - "Session" fixed string value
     * - exp {number} - timestamp of the session's expiration
     * - iat {number} - timestamp of the session's creation
     * - accountId {string} - the session account identifier
     * - authorizations {object} - object with session authorized clients and their session identifiers
     * - loginTs {number} - timestamp of user's authentication
     * - acr {string} - authentication context class reference value
     * - amr {string[]} - Authentication methods references
     * - transient {boolean} - whether the session is using a persistant or session cookie
     * - state: {object} - temporary objects used for one-time csrf and state persistance between
     *     form submissions
     *
     * Short-lived Interaction model payload contains the following properties:
     * - jti {string} - unique identifier of the interaction session
     * - kind {string} - "Interaction" fixed string value
     * - exp {number} - timestamp of the interaction's expiration
     * - iat {number} - timestamp of the interaction's creation
     * - returnTo {string} - after resolving interactions send the user-agent to this url
     * - deviceCode {string} - [DeviceCode user flows only] deviceCode reference
     * - parJti {string} - [PAR user flows only] PushedAuthorizationCode uid reference
     * - params {object} - parsed recognized parameters object
     * - lastSubmission {object} - previous interaction result submission
     * - trusted {string[]} - parameter names that come from a trusted source
     * - result {object} - interaction results object is expected here
     * - grantId {string} - grant identifier if there's a preexisting one
     * - cid {string} - correlating identifier for the Authorization request
     * - session {object}
     * - session.uid {string} - uid of the session this Interaction belongs to
     * - session.cookie {string} - jti of the session this Interaction belongs to
     * - session.acr {string} - existing acr of the session Interaction belongs to
     * - session.amr {string[]} - existing amr of the session Interaction belongs to
     * - session.accountId {string} - existing account id from the seession Interaction belongs to
     *
     * Replay prevention ReplayDetection model contains the following properties:
     * - jti {string} - unique identifier of the replay object
     * - kind {string} - "ReplayDetection" fixed string value
     * - exp {number} - timestamp of the replay object cache expiration
     * - iat {number} - timestamp of the replay object cache's creation
     */
  }

  /**
   *
   * Return previously stored instance of an oidc-provider model.
   *
   * @return {Promise} Promise fulfilled with what was previously stored for the id (when found and
   * not dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async find(id) {

  }

  /**
   *
   * Return previously stored instance of DeviceCode by the end-user entered user code. You only
   * need this method for the deviceFlow feature
   *
   * @return {Promise} Promise fulfilled with the stored device code object (when found and not
   * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} userCode the user_code value associated with a DeviceCode instance
   *
   */
  async findByUserCode(userCode) {

  }

  /**
   *
   * Return previously stored instance of Session by its uid reference property.
   *
   * @return {Promise} Promise fulfilled with the stored session object (when found and not
   * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} uid the uid value associated with a Session instance
   *
   */
  async findByUid(uid) {

  }

  /**
   *
   * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
   * id should be fulfilled with an object containing additional property named "consumed" with a
   * truthy value (timestamp, date, boolean, etc).
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async consume(id) {

  }

  /**
   *
   * Destroy/Drop/Remove a stored oidc-provider model. Future finds for this id should be fulfilled
   * with falsy values.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async destroy(id) {

  }

  /**
   *
   * Destroy/Drop/Remove a stored oidc-provider model by its grantId property reference. Future
   * finds for all tokens having this grantId value should be fulfilled with falsy values.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} grantId the grantId value associated with a this model's instance
   *
   */
  async revokeByGrantId(grantId) {

  }
}

export default MyAdapter;
