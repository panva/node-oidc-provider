/// <reference types="node" />
// TypeScript Version: 3.6

import * as events from 'events';
import * as http from 'http';
import * as http2 from 'http2';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';

import * as jose from 'jose';
import * as Koa from 'koa';

export {};

export type CanBePromise<T> = Promise<T> | T;
export type RetryFunction = (retry: number, error: Error) => number;
export type FindAccount = (ctx: KoaContextWithOIDC, sub: string, token?: AuthorizationCode | AccessToken | DeviceCode) => CanBePromise<Account>;
export type TokenFormat = 'opaque' | 'jwt' | 'jwt-ietf' | 'paseto';

export type AccessTokenFormatFunction = (ctx: KoaContextWithOIDC, token: AccessToken) => TokenFormat;
export type ClientCredentialsFormatFunction = (ctx: KoaContextWithOIDC, token: ClientCredentials) => TokenFormat;

export type TTLFunction<T> = (ctx: KoaContextWithOIDC, token: T, client: Client) => number;

export interface AnyObject {
  [key: string]: any;
}

/**
 * @see https://github.com/sindresorhus/got/tree/v9.6.0#options
 */
export interface HttpRequestOptions extends tls.SecureContextOptions {
  url?: string;
  headers?: AnyObject;
  query?: AnyObject;
  body?: AnyObject;
  form?: boolean;
  json?: boolean;
  timeout?: number | {
    lookup?: number;
    connect?: number;
    secureConnect?: number;
    socket?: number;
    response?: number;
    send?: number;
    request?: number;
  };
  retry?: number | {
    retries?: number | RetryFunction;
    methods?: Array<'GET' | 'POST' | 'PUT' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE'>;
    statusCodes?: Array<408 | 413 | 429 | 500 | 502 | 503 | 504>;
    maxRetryAfter?: number;
    errorCodes?: string[];
  };
  followRedirect?: boolean;
  throwHttpErrors?: boolean;
  agent?: http.Agent | https.Agent | boolean | {
    http: http.Agent,
    https: https.Agent,
  };

  [key: string]: any;
}

export interface AnyClientMetadata {
  /**
   * Unique Client Identifier. It MUST NOT be currently valid for any
   * other registered Client.
   */
  client_id?: string;
  /**
   * Array of `request_uri` values that are pre-registered by the
   * RP for use at the OP. Servers MAY cache the contents of the files
   * referenced by these URIs and not retrieve them at the time they are
   * used in a request. OPs can require that `request_uri` values used be
   * pre-registered with the `require_request_uri_registration` discovery
   * parameter. If the contents of the request file could ever change, these
   * URI values SHOULD include the base64url encoded `SHA-256` hash value of
   * the file contents referenced by the URI as the value of the URI fragment.
   * If the fragment value used for a URI changes, that signals the server
   * that its cached value for that URI with the
   * old fragmentalue is no longer valid.
   */
  redirect_uris?: string[];
  /**
   * JSON array containing a list of the {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0} Grant Types that the Client is declaring that it will restrict itself to using. The Grant Type values used by OpenID Connect are:
   *
   *
   * * `authorization_code`: The Authorization Code Grant Type described in {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0} Section 4.1.
   * * `implicit`: The Implicit Grant Type described in {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0} Section 4.2.
   * * `refresh_token`: The Refresh Token Grant Type described in {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0} Section 6.
   *
   *
   * The following table lists the correspondence between `response_type` values that the Client will use and grant_type values that MUST be included in the registered `grant_types` list:
   *
   * * `code`: `authorization_code`
   * * `id_token`: `implicit`
   * * `token` `id_token`: `implicit`
   * * `code` `id_token`: `authorization_code`, `implicit`
   * * `code` `token`: `authorization_code`, `implicit`
   * * `code` `token` `id_token`: `authorization_code`, `implicit`
   *
   * If omitted, the default is that the Client will use only the `authorization_code` Grant Type.
   */
  grant_types?: string[];
  /**
   * JSON array containing a list of the
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0}
   * `response_type` values that the Client is declaring that it will restrict
   * itself to using. If omitted, the default is that the Client will use only
   * the code Response Type.
   */
  response_types?: ResponseType[];

  /**
   * Kind of the application. The default, if omitted, is `web`. The defined
   * values are `native` or `web`. Web Clients using the OAuth Implicit Grant
   * Type MUST only register URLs using the `https` scheme as `redirect_uris`;
   * they MUST NOT use `localhost` as the hostname. Native Clients MUST only
   * register `redirect_uris` using custom URI schemes or URLs using the `http:`
   * scheme with `localhost` as the hostname. Authorization Servers MAY place
   * additional constraints on Native Clients. Authorization Servers MAY reject
   * Redirection URI values using the `http` scheme, other than the `localhost`
   * case for Native Clients. The Authorization Server MUST verify that all the
   * registered `redirect_uris` conform to these constraints. This prevents
   * sharing a Client ID across different types of Clients.
   */
  application_type?: 'web' | 'native';
  client_id_issued_at?: number;
  /**
   * Name of the Client to be presented to the End-User. If desired,
   * representation of this Claim in different languages and scripts is
   * represented as described in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts Section 2.1}.
   */
  client_name?: string;
  /**
   * if `client_secret` is issued. Time at which the `client_secret` will
   * expire or 0 if it will not expire. Its value is a JSON number representing
   * the number of seconds from `1970-01-01T0:0:0Z` as measured in `UTC` until the
   * `date/time`.
   */
  client_secret_expires_at?: number;
  /**
   * Client Secret. The same Client Secret value MUST NOT be assigned
   * to multiple Clients. This value is used by Confidential Clients to
   * authenticate to the Token Endpoint, as described in Section 2.3.1 of
   * OAuth 2.0, and for the derivation of symmetric encryption key values, as
   * described in Section 10.2 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core].
   * It is not needed for Clients selecting a `token_endpoint_auth_method` of
   * `private_key_jwt` unless symmetric encryption will be used.
   */
  client_secret?: string;
  /**
   * URL of the home page of the Client. The value of this field MUST point to
   * a valid Web page. If present, the server SHOULD display this URL to the
   * End-User in a followable fashion. If desired, representation of this Claim
   * in different languages and scripts is represented as described in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts Section 2.1}.
   */
  client_uri?: string;
  /**
   * Array of e-mail addresses of people responsible for this Client. This
   * might be used by some providers to enable a Web user interface to modify
   * the Client information.
   */
  contacts?: string[];
  /**
  * Default requested Authentication Context Class Reference values.
  * Array of strings that specifies the default `acr` values that the OP is
  * being requested to use for processing requests from this Client, with
  * the values appearing in order of preference. The Authentication Context
  * Class satisfied by the authentication performed is returned as the `acr`
  * Claim Value in the issued ID Token. The `acr` Claim is requested as a
  * Voluntary Claim by this parameter. The `acr_values_supported` discovery
  * element contains a list of the supported `acr` values supported by this
  * server. Values specified in the `acr_values` request parameter or an
  * individual `acr` Claim request override these default values.
  */
  default_acr_values?: string[];
  /**
   * Default Maximum Authentication Age. Specifies that the End-User
   * MUST be actively authenticated if the End-User was authenticated longer
   * ago than the specified number of seconds. The `max_age` request parameter
   * overrides this default value. If omitted, no default Maximum
   * Authentication Age is specified.
   */
  default_max_age?: number;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWS JWS} `alg` algorithm {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]} REQUIRED for signing the ID Token
   * issued to this Client. The value `none` MUST NOT be used as the ID Token
   * `alg` value unless the Client uses only Response Types that return no
   * ID Token from the Authorization Endpoint (such as when only using the
   * Authorization Code Flow). The default, if omitted, is `RS256`. The public
   * key for validating the signature is provided by retrieving the JWK Set
   * referenced by the `jwks_uri` element from
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Discovery OpenID Connect Discovery 1.0}
   * [OpenID.Discovery].
   */
  id_token_signed_response_alg?: SigningAlgorithmWithNone;
  /**
  * URI using the `https` scheme that a third party can use to
  * initiate a login by the RP, as specified in Section 4 of
  * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core].
  * The URI MUST accept requests via both `GET` and `POST`. The Client MUST
  * understand the `login_hint` and `iss` parameters and SHOULD support the
  * `target_link_uri` parameter.
  */
  initiate_login_uri?: string;
  /**
   * URL for the Client's JSON Web Key Set `[JWK]` document. If the Client
   * signs requests to the Server, it contains the signing key(s) the Server
   * uses to validate signatures from the Client. The JWK Set MAY also contain
   * the Client's encryption keys(s), which are used by the Server to encrypt
   * responses to the Client. When both signing and encryption keys are made
   * available, a `use` (Key Use) parameter value is REQUIRED for all keys in
   * the referenced JWK Set to indicate each key's intended usage. Although
   * some algorithms allow the same key to be used for both signatures and
   * encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK
   * `x5c` parameter MAY be used to provide X.509 representations of keys
   * provided. When used, the bare key values MUST still be present and MUST
   * match those in the certificate.
   */
  jwks_uri?: string;
  /**
   * Client's JSON Web Key Set `[JWK]` document, passed by value. The
   * semantics of the `jwks` parameter are the same as the `jwks_uri` parameter,
   * other than that the JWK Set is passed by value, rather than by reference.
   * This parameter is intended only to be used by Clients that, for some
   * reason, are unable to use the `jwks_uri` parameter, for instance, by native
   * applications that might not have a location to host the contents of the
   * JWK Set. If a Client can use `jwks_uri`, it MUST NOT use jwks. One
   * significant downside of `jwks` is that it does not enable key rotation
   * (which `jwks_uri` does, as described in Section 10 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core]}).

   * The `jwks_uri` and `jwks` parameters MUST NOT be used together.
   */
  jwks?: jose.JSONWebKeySet;
  /**
   * URL that references a logo for the Client application. If present, the
   * server SHOULD display this image to the End-User during approval. The
   * value of this field MUST point to a valid image file. If desired,
   * representation of this Claim in different languages and scripts is
   * represented as described in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts Section 2.1}.
   */
  logo_uri?: string;
  /**
   * URL that the Relying Party Client provides to the End-User to read about
   * the how the profile data will be used. The value of this field MUST point
   * to a valid web page. The OpenID Provider SHOULD display this URL to the
   * End-User if it is given. If desired, representation of this Claim in
   * different languages and scripts is represented as described in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts Section 2.1}.
   */
  policy_uri?: string;
  post_logout_redirect_uris?: string[];
  /**
   * Boolean value specifying whether the `auth_time` Claim in the
   * ID Token is REQUIRED. It is REQUIRED when the value is `true`. (If this
   * is `false`, the `auth_time` Claim can still be dynamically requested as an
   * individual Claim for the ID Token using the `claims` request parameter
   * described in Section 5.5.1 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core].)
   * If omitted, the default value is `false`.
   */
  require_auth_time?: boolean;
  scope?: string;
  /**
   * URL using the `https` scheme to be used in calculating
   * Pseudonymous Identifiers by the OP. The URL references a file with a
   * single JSON array of `redirect_uri` values. Please see
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation Section 5}.
   * Providers that use pairwise `sub` (subject) values SHOULD utilize the
   * `sector_identifier_uri` value provided in the Subject Identifier calculation
   * for pairwise identifiers.
   */
  sector_identifier_uri?: string;
  /**
   * `subject_type` requested for responses to this Client. The
   * `subject_types_supported` Discovery parameter contains a list of the
   * supported `subject_type` values for this server. Valid types include
   * `pairwise` and `public`.
   */
  subject_type?: SubjectTypes;
  /**
   * Requested Client Authentication method for the Token Endpoint.
   * The options are `client_secret_post`, `client_secret_basic`,
   * `client_secret_jwt`, `private_key_jwt`, and `none`, as described in Section 9 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core].
   * Other authentication methods MAY be defined by extensions. If omitted,
   * the default is `client_secret_basic` -- the HTTP Basic Authentication
   * Scheme specified in Section 2.3.1 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#RFC6749 OAuth 2.0} [RFC6749].
   */
  token_endpoint_auth_method?: ClientAuthMethod;
  /**
   * URL that the Relying Party Client provides to the End-User to read about
   * the Relying Party's terms of service. The value of this field MUST point
   * to a valid web page. The OpenID Provider SHOULD display this URL to the
   * End-User if it is given. If desired, representation of this Claim in
   * different languages and scripts is represented as described in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts Section 2.1}.
   */
  tos_uri?: string;

  tls_client_auth_subject_dn?: string;
  tls_client_auth_san_dns?: string;
  tls_client_auth_san_uri?: string;
  tls_client_auth_san_ip?: string;
  tls_client_auth_san_email?: string;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWS JWS} [JWS]
   * `alg` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * that MUST be used for signing the JWT
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWT [JWT]}
   * used to authenticate the Client at the Token Endpoint for the
   * `private_key_jwt` and `client_secret_jwt` authentication methods. All Token
   * Requests using these authentication methods from this Client MUST be
   * rejected, if the JWT is not signed with this algorithm. Servers SHOULD
   * support `RS256`. The value `none` MUST NOT be used. The default, if
   * omitted, is that any algorithm supported by the OP and the RP MAY be used.
   */
  token_endpoint_auth_signing_alg?: SigningAlgorithm;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWS JWS} `alg` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * REQUIRED for signing UserInfo Responses. If this is specified, the response
   * will be JWT {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWT [JWT]}
   * serialized, and signed using {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWS JWS}.
   * The default, if omitted, is for the UserInfo Response to return the Claims
   * as a UTF-8 encoded JSON object using the `application/json` content-type.
   */
  userinfo_signed_response_alg?: SigningAlgorithmWithNone;
  introspection_endpoint_auth_method?: ClientAuthMethod;
  introspection_endpoint_auth_signing_alg?: SigningAlgorithm;
  introspection_signed_response_alg?: SigningAlgorithmWithNone;
  introspection_encrypted_response_alg?: EncryptionAlgValues;
  introspection_encrypted_response_enc?: EncryptionEncValues;
  revocation_endpoint_auth_method?: ClientAuthMethod;
  revocation_endpoint_auth_signing_alg?: SigningAlgorithm;
  backchannel_logout_session_required?: boolean;
  backchannel_logout_uri?: string;
  frontchannel_logout_session_required?: boolean;
  frontchannel_logout_uri?: string;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWS JWS} [JWS]
   * `alg` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * that MUST be used for signing Request Objects sent to the OP. All Request
   * Objects from this Client MUST be rejected, if not signed with this
   * algorithm. Request Objects are described in Section 6.1 of
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core OpenID Connect Core 1.0} [OpenID.Core].
   * This algorithm MUST be used both when the Request Object is passed by
   * value (using the request parameter) and when it is passed by reference
   * (using the request_uri parameter). Servers SHOULD support `RS256`. The
   * value `none` MAY be used. The default, if omitted, is that any algorithm
   * supported by the OP and the RP MAY be used.
   */
  request_object_signing_alg?: SigningAlgorithmWithNone;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE} [JWE]
   * `alg` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * the RP is declaring that it may use for encrypting Request Objects
   * sent to the OP. This parameter SHOULD be included when symmetric
   * encryption will be used, since this signals to the OP that a `client_secret`
   * value needs to be returned from which the symmetric key will be derived,
   * that might not otherwise be returned. The RP MAY still use other supported
   * encryption algorithms or send unencrypted Request Objects, even when this
   * parameter is present. If both signing and encryption are requested, the
   * Request Object will be signed then encrypted, with the result being a
   * Nested JWT, as defined in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWT [JWT]}.
   * The default, if omitted, is that the RP is not declaring whether it might
   * encrypt any Request Objects.
   */
  request_object_encryption_alg?: EncryptionAlgValues;
  /**
   * OPTIONAL.
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE}
   * `enc` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * the RP is declaring that it may use for encrypting Request Objects sent
   * to the OP. If `request_object_encryption_alg` is specified, the default for
   * this value is `A128CBC-HS256`. When `request_object_encryption_enc` is
   * included, `request_object_encryption_alg` MUST also be provided.
   */
  request_object_encryption_enc?: EncryptionEncValues;
  /**
   * Array of `request_uri` values that are pre-registered by the
   * RP for use at the OP. Servers MAY cache the contents of the files
   * referenced by these URIs and not retrieve them at the time they are
   * used in a request. OPs can require that `request_uri` values used be
   * pre-registered with the `require_request_uri_registration` discovery
   * parameter. If the contents of the request file could ever change, these
   * URI values SHOULD include the base64url encoded `SHA-256` hash value of
   * the file contents referenced by the URI as the value of the URI fragment.
   * If the fragment value used for a URI changes, that signals the server
   * that its cached value for that URI with the
   * old fragmentalue is no longer valid.
   */
  request_uris?: string[];
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE}
   * `alg` algorithm {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * REQUIRED for encrypting the ID Token issued to this Client. If this is
   * requested, the response will be signed then encrypted, with the result
   * being a Nested JWT, as defined in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWT [JWT]}.
   * The default, if omitted, is that no encryption is performed.
   */
  id_token_encrypted_response_alg?: EncryptionAlgValues;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE}
   * `enc` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * REQUIRED for encrypting the ID Token issued to this Client. If
   * `id_token_encrypted_response_alg` is specified, the default for this value
   * is `A128CBC`-`HS256`. When `id_token_encrypted_response_enc` is included,
   * `id_token_encrypted_response_alg` MUST also be provided.
   */
  id_token_encrypted_response_enc?: EncryptionEncValues;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE}
   * [JWE] `alg` algorithm {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * REQUIRED for encrypting UserInfo Responses. If both signing and encryption
   * are requested, the response will be signed then encrypted, with the result
   * being a Nested JWT, as defined in
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWT [JWT]}.
   * The default, if omitted, is that no encryption is performed.
   */
  userinfo_encrypted_response_alg?: EncryptionAlgValues;
  /**
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWE JWE}
   * `enc` algorithm
   * {@link https://openid.net/specs/openid-connect-registration-1_0.html#JWA [JWA]}
   * REQUIRED for encrypting UserInfo Responses. If `userinfo_encrypted_response_alg`
   * is specified, the default for this value is `A128CBC-HS256`. When
   * `userinfo_encrypted_response_enc` is included, `userinfo_encrypted_response_alg`
   * MUST also be provided.
   */
  userinfo_encrypted_response_enc?: EncryptionEncValues;
  authorization_signed_response_alg?: SigningAlgorithm;
  authorization_encrypted_response_alg?: EncryptionAlgValues;
  authorization_encrypted_response_enc?: EncryptionEncValues;
  web_message_uris?: string[];
  tls_client_certificate_bound_access_tokens?: boolean;

  [key: string]: any;
}

export interface ClientMetadata extends AnyClientMetadata {
  /**
   * Unique Client Identifier. It MUST NOT be currently valid for any
   * other registered Client.
   */
  client_id: string;
  /**
   * Array of `request_uri` values that are pre-registered by the
   * RP for use at the OP. Servers MAY cache the contents of the files
   * referenced by these URIs and not retrieve them at the time they are
   * used in a request. OPs can require that `request_uri` values used be
   * pre-registered with the `require_request_uri_registration` discovery
   * parameter. If the contents of the request file could ever change, these
   * URI values SHOULD include the base64url encoded `SHA-256` hash value of
   * the file contents referenced by the URI as the value of the URI fragment.
   * If the fragment value used for a URI changes, that signals the server
   * that its cached value for that URI with the
   * old fragmentalue is no longer valid.
   */
  redirect_uris: string[];
}

export type ResponseType = 'code' | 'id_token' | 'code id_token' | 'id_token token' | 'code token' | 'code id_token token' | 'none';
export type PKCEMethods = 'S256' | 'plain';
export type SubjectTypes = 'public' | 'pairwise';
export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'tls_client_auth' | 'self_signed_tls_client_auth' | 'none';

export interface ClaimsParameterMember {
  essential?: boolean;
  value?: string;
  values?: string[];

  [key: string]: any;
}

export interface ClaimsParameter {
  id_token?: {
    [key: string]: null | ClaimsParameterMember
  };
  userinfo?: {
    [key: string]: null | ClaimsParameterMember
  };
}

export interface ClaimsWithRejects extends ClaimsParameter {
  rejected?: string[];
}

export interface ClientAuthorizationState {
  persistsLogout?: boolean;
  sid?: string;
  grantId?: string;
  meta?: AnyObject;
  rejectedScopes?: string[];
  rejectedClaims?: string[];
  promptedClaims?: string[];
  promptedScopes?: string[];
}

export interface PromptDetail {
  name: 'login' | 'consent' | string;
  reasons: string[];
  details: AnyObject;
}

declare class Interaction extends BaseModel {
  readonly kind: 'Interaction';
  iat: number;
  exp: number;
  session?: Session | {
    accountId: string;
    cookie: string;
    jti?: string;
    acr?: string;
    amr?: string[];
  };
  params: AnyObject;
  prompt: PromptDetail;
  result: InteractionResults;
  returnTo: string;
  signed?: string[];
  uid: string;
  lastSubmission?: InteractionResults;

  save(ttl?: number): Promise<string>;
}

declare class Session extends BaseModel {
  readonly kind: 'Session';
  iat: number;
  exp: number;
  uid: string;
  jti: string;

  account?: string;
  acr?: string;
  amr?: string[];
  loginTs?: number;
  transient?: boolean;
  state?: AnyObject;
  authorizations?: {
    [clientId: string]: ClientAuthorizationState;
  };

  accountId(): string | void;
  authTime(): string | void;
  past(age: number): boolean;

  ensureClientContainer(clientId: string): void;
  loginAccount(details: {
    account: string;
    acr?: string;
    amr?: string[];
    loginTs?: number;
    transient?: boolean;
  }): void;
  authorizationFor(clientId: string): ClientAuthorizationState | void;
  stateFor(clientId: string): string;
  sidFor(clientId: string): string;
  sidFor(clientId: string, value: string): void;
  grantIdFor(clientId: string): string;
  grantIdFor(clientId: string, value: string): void;
  metaFor(clientId: string): AnyObject | void;
  metaFor(clientId: string, value: string): void;
  acceptedScopesFor(clientId: string): Set<string>;
  acceptedClaimsFor(clientId: string): Set<string>;
  promptedScopesFor(clientId: string): Set<string>;
  promptedScopesFor(clientId: string, scopes: string[]): void;
  promptedClaimsFor(clientId: string): Set<string>;
  promptedClaimsFor(clientId: string, claims: string[]): void;
  rejectedScopesFor(clientId: string): Set<string>;
  rejectedScopesFor(clientId: string, scopes: string[], replace?: boolean): void;
  rejectedClaimsFor(clientId: string): Set<string>;
  rejectedClaimsFor(clientId: string, claims: string[], replace?: boolean): void;

  save(ttl?: number): Promise<string>;
  destroy(): Promise<void>;
  resetIdentifier(): void;
  static find<T>(this: { new (...args: any[]): T }, cookieId: string): Promise<T | undefined>;
  static findByUid(uid: string): Promise<Session | undefined>;
  static get(ctx: Koa.Context): Promise<Session>;
}

declare class RequestUriCache {
  resolveUrn(urn: string): Promise<string>;
  resolveWebUri(requestUri: string): Promise<string>;
}

declare class JWTStructured {
  header?: AnyObject;
  payload: AnyObject;
}

declare class PASETOStructured {
  footer?: AnyObject | Buffer | string;
  payload: AnyObject;
}

interface BaseModel {
  jti: string;
  kind: string;
  iat?: number;
  exp?: number;
}

declare class BaseModel {
  readonly adapter: Adapter;

  save(ttl?: number): Promise<string>;
  destroy(): Promise<void>;
  emit(eventName: string): void;

  static readonly adapter: Adapter;

  static IN_PAYLOAD: string[];

  static find<T>(
    this: { new (...args: any[]): T },
    id: string,
    options?: object
  ): Promise<T | undefined>;
}

declare class BaseToken extends BaseModel {
  iat: number;
  exp?: number;
  jti: string;
  readonly kind: string;
  clientId?: string;
  client?: Client;
  readonly format?: string;
  readonly scopes: Set<string>;

  ttlPercentagePassed(): number;

  readonly isValid: boolean;
  readonly isExpired: boolean;
  readonly remainingTTL: number;
  readonly expiration: number;

  static IN_PAYLOAD: string[];

  static find<T>(this: { new (...args: any[]): T }, jti: string, options?: { ignoreExpiration?: boolean }): Promise<T | undefined>;
  save(): Promise<string>;

  readonly adapter: Adapter;
  static readonly adapter: Adapter;
}

declare class ReplayDetection {
  readonly kind: 'ReplayDetection';
  unique(iss: string, jti: string, exp?: number): Promise<boolean>;

  readonly adapter: Adapter;
  static readonly adapter: Adapter;
}

declare class PushedAuthorizationRequest extends BaseToken {
  constructor(properties: { request: string });
  readonly kind: 'PushedAuthorizationRequest';
  request: string;
}

declare class RefreshToken extends BaseToken {
  constructor(properties: {
    client: Client;
    accountId: string;
    acr?: string;
    amr?: string[];
    authTime?: number;
    claims?: ClaimsWithRejects;
    nonce?: string;
    resource?: string | string[];
    scope: string;
    sid?: string;
    sessionUid?: string;
    expiresWithSession?: boolean;
    'x5t#S256'?: string;
    jkt?: string;
    grantId: string;
    gty: string;
    [key: string]: any;
  });
  readonly kind: 'RefreshToken';
  rotations?: number;
  iiat?: number;
  accountId: string;
  acr?: string;
  amr?: string[];
  authTime?: number;
  claims?: ClaimsWithRejects;
  nonce?: string;
  resource?: string | string[];
  scope?: string;
  sid?: string;
  sessionUid?: string;
  expiresWithSession?: boolean;
  'x5t#S256'?: string;
  jkt?: string;
  grantId?: string;
  gty?: string;
  consumed: any;

  totalLifetime(): number;
  isSenderConstrained(): boolean;
  consume(): Promise<void>;
}

declare class AuthorizationCode extends BaseToken {
  constructor(properties: {
    client: Client;
    accountId: string;
    redirectUri?: string;
    acr?: string;
    amr?: string[];
    authTime?: number;
    claims?: ClaimsWithRejects;
    nonce?: string;
    resource?: string | string[];
    codeChallenge?: string;
    codeChallengeMethod?: string;
    scope: string;
    sid?: string;
    sessionUid?: string;
    expiresWithSession?: boolean;
    'x5t#S256'?: string;
    jkt?: string;
    grantId: string;
    gty: string;
    [key: string]: any;
  });
  readonly kind: 'AuthorizationCode';
  redirectUri?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  accountId?: string;
  acr?: string;
  amr?: string[];
  authTime?: number;
  claims?: ClaimsWithRejects;
  nonce?: string;
  resource?: string | string[];
  scope?: string;
  sid?: string;
  sessionUid?: string;
  expiresWithSession?: boolean;
  'x5t#S256'?: string;
  jkt?: string;
  grantId?: string;
  gty?: string;

  consume(): Promise<void>;
}

declare class DeviceCode extends BaseToken {
  constructor(properties: {
    params: AnyObject;
    userCode: string;
    grantId: string;
    client: Client;
    deviceInfo: AnyObject;
    [key: string]: any;
  });

  static findByUserCode(userCode: string, options?: { ignoreExpiration?: boolean }): Promise<DeviceCode | undefined>;

  readonly kind: 'DeviceCode';
  error?: string;
  errorDescription?: string;
  params?: AnyObject;
  userCode: string;
  inFlight?: boolean;
  deviceInfo?: AnyObject;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  accountId?: string;
  acr?: string;
  amr?: string[];
  authTime?: number;
  claims?: ClaimsWithRejects;
  nonce?: string;
  resource?: string | string[];
  scope?: string;
  sid?: string;
  sessionUid?: string;
  expiresWithSession?: boolean;
  grantId: string;
  gty: string;
  consumed: any;

  consume(): Promise<void>;
}

declare class ClientCredentials extends BaseToken {
  constructor(properties: {
    client: Client;
    resource?: string | string[];
    scope: string;
    [key: string]: any;
  });
  readonly kind: 'ClientCredentials';
  scope?: string;
  extra?: AnyObject;
  aud: string | string[];
  readonly tokenType: string;
  'x5t#S256'?: string;
  jkt?: string;

  setAudiences(audience: string | string[]): void;
  isSenderConstrained(): boolean;
}

declare class InitialAccessToken extends BaseToken {
  constructor(properties?: {
    expiresIn?: number;
    policies?: string[];
    [key: string]: any;
  });
  readonly kind: 'InitialAccessToken';
  clientId: undefined;
  policies?: string[];
}

declare class RegistrationAccessToken extends BaseToken {
  readonly kind: 'RegistrationAccessToken';
  policies?: string[];
}

declare class AccessToken extends BaseToken {
  constructor(properties: {
    client: Client;
    accountId: string;
    claims?: ClaimsWithRejects;
    aud?: string | string[];
    scope: string;
    sid?: string;
    sessionUid?: string;
    expiresWithSession?: boolean;
    'x5t#S256'?: string;
    jkt?: string;
    grantId: string;
    gty: string;
    [key: string]: any;
  });
  readonly kind: 'AccessToken';
  accountId: string;
  aud: string | string[];
  claims?: ClaimsWithRejects;
  extra?: AnyObject;
  grantId: string;
  scope?: string;
  gty: string;
  sid?: string;
  sessionUid?: string;
  expiresWithSession?: boolean;
  readonly tokenType: string;
  'x5t#S256'?: string;
  jkt?: string;

  setAudiences(audience: string | string[]): void;
  isSenderConstrained(): boolean;
}

declare class IdToken {
  constructor(claims: AnyObject, context?: { ctx?: KoaContextWithOIDC, client?: Client });

  readonly ctx: KoaContextWithOIDC;
  readonly client: Client;
  readonly available: AnyObject;
  readonly extra: AnyObject;

  set(key: string, value: any): void;
  payload(): Promise<AnyObject>;
  issue(context?: { use: 'idtoken' | 'logout' | 'userinfo' | 'introspection' | 'authorization', expiresAt?: number }): Promise<string>;
  validate(idToken: string, client: Client): Promise<{ header: AnyObject, payload: AnyObject }>;
}

declare class ClientKeystore {
  fresh(): boolean;
  stale(): boolean;
  refresh(): Promise<void>;
  readonly size: number;
  all(parameters?: jose.JWKS.KeyQuery): jose.JWK.Key[];
  get(parameters?: jose.JWKS.KeyQuery): jose.JWK.Key;
  toJWKS(private?: boolean): jose.JSONWebKeySet;
}

declare class Client {
  responseTypeAllowed(type: ResponseType): boolean;
  grantTypeAllowed(type: string): boolean;
  redirectUriAllowed(redirectUri: string): boolean;
  checkSessionOriginAllowed(origin: string): boolean;
  webMessageUriAllowed(webMessageUri: string): boolean;
  requestUriAllowed(requestUri: string): boolean;
  postLogoutRedirectUriAllowed(postLogoutRedirectUri: string): boolean;
  includeSid(): boolean;
  compareClientSecret(actual: string): CanBePromise<boolean>;

  metadata(): ClientMetadata;

  readonly clientId: string;
  readonly keystore: ClientKeystore;

  readonlyclientId: string;

  readonly grantTypes?: string[];
  readonly redirectUris?: string[];
  readonly responseTypes?: ResponseType[];

  readonly applicationType?: 'web' | 'native';
  readonly clientIdIssuedAt?: number;
  readonly clientName?: string;
  readonly clientSecretExpiresAt?: number;
  readonly clientSecret?: string;
  readonly clientUri?: string;
  readonly contacts?: string[];
  readonly defaultAcrValues?: string[];
  readonly defaultMaxAge?: number;
  readonly idTokenSignedResponseAlg?: string;
  readonly initiateLoginUri?: string;
  readonly jwksUri?: string;
  readonly jwks?: jose.JSONWebKeySet;
  readonly logoUri?: string;
  readonly policyUri?: string;
  readonly postLogoutRedirectUris?: string[];
  readonly requireAuthTime?: boolean;
  readonly scope?: string;
  readonly sectorIdentifierUri?: string;
  readonly subjectType?: SubjectTypes;
  readonly tokenEndpointAuthMethod?: string;
  readonly tosUri?: string;

  readonly tlsClientAuthSubjectDn?: string;
  readonly tlsClientAuthSanDns?: string;
  readonly tlsClientAuthSanUri?: string;
  readonly tlsClientAuthSanIp?: string;
  readonly tlsClientAuthSanEmail?: string;
  readonly tokenEndpointAuthSigningAlg?: string;
  readonly userinfoSignedResponseAlg?: string;
  readonly introspectionEndpointAuthMethod?: string;
  readonly introspectionEndpointAuthSigningAlg?: string;
  readonly introspectionSignedResponseAlg?: string;
  readonly introspectionEncryptedResponseAlg?: string;
  readonly introspectionEncryptedResponseEnc?: string;
  readonly revocationEndpointAuthMethod?: string;
  readonly revocationEndpointAuthSigningAlg?: string;
  readonly backchannelLogoutSessionRequired?: boolean;
  readonly backchannelLogoutUri?: string;
  readonly frontchannelLogoutSessionRequired?: boolean;
  readonly frontchannelLogoutUri?: string;
  readonly requestObjectSigningAlg?: string;
  readonly requestObjectEncryptionAlg?: string;
  readonly requestObjectEncryptionEnc?: string;
  readonly requestUris?: string[];
  readonly idTokenEncryptedResponseAlg?: string;
  readonly idTokenEncryptedResponseEnc?: string;
  readonly userinfoEncryptedResponseAlg?: string;
  readonly userinfoEncryptedResponseEnc?: string;
  readonly authorizationSignedResponseAlg?: string;
  readonly authorizationEncryptedResponseAlg?: string;
  readonly authorizationEncryptedResponseEnc?: string;
  readonly webMessageUris?: string[];
  readonly tlsClientCertificateBoundAccessTokens?: boolean;

  [key: string]: any;

  static find(id: string): Promise<Client | undefined>;
}

declare class OIDCContext {
  constructor(ctx: Koa.Context);
  readonly route: string;
  uid: string;

  readonly cookies: {
    get(name: string, opts?: { signed?: boolean }): string | undefined;
    set(name: string, value: string | null, opts?: CookiesSetOptions): undefined;
  };

  readonly entities: {
    readonly AccessToken?: AccessToken;
    readonly Account?: Account;
    readonly AuthorizationCode?: AuthorizationCode;
    readonly Client?: Client;
    readonly ClientCredentials?: ClientCredentials;
    readonly DeviceCode?: DeviceCode;
    readonly IdTokenHint?: { header: AnyObject, payload: AnyObject };
    readonly InitialAccessToken?: InitialAccessToken;
    readonly Interaction?: Interaction;
    readonly PushedAuthorizationRequest?: PushedAuthorizationRequest;
    readonly RefreshToken?: RefreshToken;
    readonly RegistrationAccessToken?: RegistrationAccessToken;
    readonly RotatedRefreshToken?: RefreshToken;
    readonly RotatedRegistrationAccessToken?: RegistrationAccessToken;
    readonly Session?: Session;
    readonly [key: string]: any;
  };
  readonly claims: ClaimsParameter;
  readonly issuer: string;
  readonly provider: Provider;

  entity(key: string, value: any): void;

  promptPending(name: string): boolean;

  readonly requestParamClaims: Set<string>;
  readonly requestParamScopes: Set<string>;
  readonly prompts: Set<string>;
  readonly result?: InteractionResults;

  readonly webMessageUriCheckPerformed?: boolean;
  readonly redirectUriCheckPerformed?: boolean;
  readonly signed?: string[];
  readonly registrationAccessToken?: RegistrationAccessToken;
  readonly deviceCode?: DeviceCode;
  readonly accessToken?: AccessToken;
  readonly account?: Account;
  readonly client?: Client;
  readonly session?: Session;
  readonly acr: string;
  readonly amr: string[];
  readonly body?: AnyObject;
  readonly params?: AnyObject;

  acceptedScope(): string[] | void;
  resolvedClaims(): ClaimsWithRejects;

  getAccessToken(opts?: { acceptDPoP?: boolean, acceptQueryParam?: boolean }): string;
}

export type KoaContextWithOIDC = Koa.ParameterizedContext<
  Koa.DefaultState,
  Koa.DefaultContext & {
    oidc: OIDCContext;
  }
>;

export const DYNAMIC_SCOPE_LABEL: symbol;

export type TLSClientAuthProperty = 'tls_client_auth_subject_dn' | 'tls_client_auth_san_dns' | 'tls_client_auth_san_uri' | 'tls_client_auth_san_ip' | 'tls_client_auth_san_email';

export interface AccountClaims {
  sub: string;

  [key: string]: any;
}

export interface Account {
  accountId: string;
  claims: (use: string, scope: string, claims: { [key: string]: null | ClaimsParameterMember }, rejected: string[]) => CanBePromise<AccountClaims>;
  [key: string]: any;
}

export type RotateRegistrationAccessTokenFunction = (ctx: KoaContextWithOIDC) => CanBePromise<boolean>;

export interface ErrorOut {
  error: string;
  error_description?: string;
  scope?: string;
  state?: string;
}

export interface AdapterPayload {
  account?: string;
  accountId?: string;
  acr?: string;
  amr?: string[];
  aud?: string[];
  authorizations?: {
    [clientId: string]: ClientAuthorizationState;
  };
  authTime?: number;
  claims?: ClaimsWithRejects;
  clientId?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  consumed?: any;
  deviceInfo?: AnyObject;
  error?: string;
  errorDescription?: string;
  exp?: number;
  expiresWithSession?: boolean;
  extra?: AnyObject;
  format?: string;
  grantId?: string;
  gty?: string;
  iat?: number;
  iiat?: number;
  inFlight?: boolean;
  jti?: string;
  jwt?: string;
  kind?: string;
  lastSubmission?: InteractionResults;
  loginTs?: number;
  nonce?: string;
  params?: AnyObject;
  paseto?: string;
  policies?: string[];
  redirectUri?: string;
  request?: string;
  resource?: string;
  result?: InteractionResults;
  returnTo?: string;
  rotations?: number;
  scope?: string;
  session?: {
    accountId?: string;
    acr?: string;
    amr?: string[];
    cookie?: string;
    uid?: string;
  };
  sessionUid?: string;
  sid?: string;
  signed?: string[];
  state?: AnyObject;
  transient?: boolean;
  uid?: string;
  userCode?: string;
  jkt?: string;
  'jwt-ietf'?: string;
  'x5t#S256'?: string;
}

export interface Adapter {
  upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<undefined | void>;
  find(id: string): Promise<AdapterPayload | undefined | void>;
  findByUserCode(userCode: string): Promise<AdapterPayload | undefined | void>;
  findByUid(uid: string): Promise<AdapterPayload | undefined | void>;
  consume(id: string): Promise<undefined | void>;
  destroy(id: string): Promise<undefined | void>;
  revokeByGrantId(grantId: string): Promise<undefined | void>;
}

export interface AdapterConstructor {
  new(name: string): Adapter;
}

export interface CookiesSetOptions {
  maxAge?: number;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  signed?: boolean;
  overwrite?: boolean;
}

export interface Configuration {
  acrValues?: string[] | Set<string>;

  adapter?: AdapterConstructor;

  claims?: {
    [key: string]: null | string[]
  };

  clientBasedCORS?: (ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean;

  clients?: ClientMetadata[];

  clientDefaults?: AnyClientMetadata;

  clockTolerance?: number;

  conformIdTokenClaims?: boolean;

  cookies?: {
    names?: {
      session?: string;
      interaction?: string;
      resume?: string;
      state?: string;
    };
    long?: CookiesSetOptions;
    short?: CookiesSetOptions;
    keys?: Array<string | Buffer>;
  };

  discovery?: AnyObject;

  extraParams?: string[];

  features?: {
    devInteractions?: {
      enabled?: boolean
    };

    claimsParameter?: {
      enabled?: boolean
    };

    clientCredentials?: {
      enabled?: boolean
    };

    introspection?: {
      enabled?: boolean
    };

    revocation?: {
      enabled?: boolean
    };

    userinfo?: {
      enabled?: boolean
    };

    jwtUserinfo?: {
      enabled?: boolean
    };

    encryption?: {
      enabled?: boolean
    };

    registration?: {
      enabled?: boolean;
      initialAccessToken?: boolean | string;
      policies?: {
        [key: string]: (ctx: KoaContextWithOIDC, metadata: ClientMetadata) => CanBePromise<void | undefined>;
      };
      idFactory?: (ctx: KoaContextWithOIDC) => string;
      secretFactory?: (ctx: KoaContextWithOIDC) => string;
    };

    registrationManagement?: {
      enabled?: boolean;
      rotateRegistrationAccessToken?: RotateRegistrationAccessTokenFunction | boolean
    };

    deviceFlow?: {
      enabled?: boolean;
      charset?: 'base-20' | 'digits';
      mask?: string;
      deviceInfo?: (ctx: KoaContextWithOIDC) => AnyObject;
      userCodeInputSource?: (ctx: KoaContextWithOIDC, form: string, out?: ErrorOut, err?: errors.OIDCProviderError | Error) => CanBePromise<void | undefined>;
      userCodeConfirmSource?: (ctx: KoaContextWithOIDC, form: string, client: Client, deviceInfo: AnyObject, userCode: string) => CanBePromise<void | undefined>;
      successSource?: (ctx: KoaContextWithOIDC) => CanBePromise<void | undefined>;
    };

    requestObjects?: {
      request?: boolean;
      requestUri?: boolean;
      requireUriRegistration?: boolean;
      mergingStrategy?: {
        name?: 'lax' | 'strict' | 'whitelist',
        whitelist?: string[] | Set<string>;
      };
    };

    dPoP?: {
      enabled?: boolean,
      iatTolerance?: number,
      ack?: 'id-03' | 'individual-draft-03' | 'individual-draft-04'
    },

    secp256k1?: {
      enabled?: boolean,
      ack?: 'draft-03' | 'draft-04' | 'draft-05'
    },

    sessionManagement?: {
      enabled?: boolean,
      keepHeaders?: boolean,
      ack?: 28 | 'draft-28',
      scriptNonce?: (ctx: KoaContextWithOIDC) => string
    },

    backchannelLogout?: {
      enabled?: boolean,
      ack?: 4 | 'draft-04'
    },

    ietfJWTAccessTokenProfile?: {
      enabled?: boolean,
      ack?: 2 | 'draft-02' | 'draft-03'
    },

    fapiRW?: {
      enabled?: boolean,
      ack?: 'id02-rev.3' | 'implementers-draft-02'
    },

    webMessageResponseMode?: {
      enabled?: boolean,
      ack?: 'id-00' | 'individual-draft-00',
      scriptNonce?: (ctx: KoaContextWithOIDC) => string
    },

    jwtIntrospection?: {
      enabled?: boolean,
      ack?: 8 | 'draft-08'
    },

    jwtResponseModes?: {
      enabled?: boolean,
      ack?: 1 | 2 | 'draft-02'
    },

    pushedAuthorizationRequests?: {
      enabled?: boolean,
      ack?: 0 | 'individual-draft-01' | 'draft-00' | 'draft-01'
    },

    mTLS?: {
      enabled?: boolean;
      certificateBoundAccessTokens?: boolean;
      selfSignedTlsClientAuth?: boolean;
      tlsClientAuth?: boolean;
      getCertificate?: (ctx: KoaContextWithOIDC) => string;
      certificateAuthorized?: (ctx: KoaContextWithOIDC) => boolean;
      certificateSubjectMatches?: (ctx: KoaContextWithOIDC, property: TLSClientAuthProperty, expected: string) => boolean;
    };

    resourceIndicators?: {
      enabled?: boolean;
      ack?: 2 | 3 | 4 | 5 | 6 | 7 | 'draft-07';
      allowedPolicy?: (ctx: KoaContextWithOIDC, resources: string | string[], client: Client) => CanBePromise<boolean>;
    };

    frontchannelLogout?: {
      enabled?: boolean;
      ack?: 2 | 'draft-02';
      logoutPendingSource?: (ctx: KoaContextWithOIDC, frames: string[], postLogoutRedirectUri?: string) => CanBePromise<void | undefined>;
    };
  };

  extraAccessTokenClaims?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials) => CanBePromise<AnyObject | void | undefined> ;

  formats?: {
    AccessToken?: AccessTokenFormatFunction | TokenFormat;
    ClientCredentials?: ClientCredentialsFormatFunction | TokenFormat;
    jwtAccessTokenSigningAlg?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, client: Client) => CanBePromise<AsymmetricSigningAlgorithm>;
    customizers?: {
      jwt?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: JWTStructured) => Promise<JWTStructured> | JWTStructured;
      'jwt-ietf'?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: JWTStructured) => Promise<JWTStructured> | JWTStructured;
      paseto?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: PASETOStructured) => Promise<PASETOStructured> | PASETOStructured;
    };
  };

  httpOptions?: (options: HttpRequestOptions) => HttpRequestOptions;

  expiresWithSession?: (ctx: KoaContextWithOIDC, token: AccessToken | AuthorizationCode | DeviceCode) => CanBePromise<boolean>;

  issueRefreshToken?: (ctx: KoaContextWithOIDC, client: Client, code: AuthorizationCode | DeviceCode) => CanBePromise<boolean>;

  jwks?: jose.JSONWebKeySet;

  responseTypes?: ResponseType[];

  pkceMethods?: PKCEMethods[];

  routes?: {
    authorization?: string;
    check_session?: string;
    code_verification?: string;
    device_authorization?: string;
    end_session?: string;
    introspection?: string;
    jwks?: string;
    registration?: string;
    revocation?: string;
    token?: string;
    userinfo?: string;
    pushed_authorization_request?: string;
  };

  scopes?: string[];

  dynamicScopes?: RegExp[];

  subjectTypes?: SubjectTypes[];

  pairwiseIdentifier?: (ctx: KoaContextWithOIDC, accountId: string, client: Client) => CanBePromise<string>;

  tokenEndpointAuthMethods?: ClientAuthMethod[];

  introspectionEndpointAuthMethods?: ClientAuthMethod[];

  revocationEndpointAuthMethods?: ClientAuthMethod[];

  ttl?: {
    AccessToken?: TTLFunction<AccessToken> | number;
    AuthorizationCode?: TTLFunction<AuthorizationCode> | number;
    ClientCredentials?: TTLFunction<ClientCredentials> | number;
    DeviceCode?: TTLFunction<DeviceCode> | number;
    IdToken?: TTLFunction<IdToken> | number;
    RefreshToken?: TTLFunction<RefreshToken> | number;

    [key: string]: any;
  };

  extraClientMetadata?: {
    properties?: string[];

    validator?: (key: string, value: any, metadata: ClientMetadata, ctx: KoaContextWithOIDC) => void | undefined;
  };

  postLogoutSuccessSource?: (ctx: KoaContextWithOIDC) => CanBePromise<void | undefined>;

  rotateRefreshToken?: ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>) | boolean;

  logoutSource?: (ctx: KoaContextWithOIDC, form: string) => CanBePromise<void | undefined>;

  renderError?: (ctx: KoaContextWithOIDC, out: ErrorOut, error: errors.OIDCProviderError | Error) => CanBePromise<void | undefined>;

  interactions?: {
    policy?: interactionPolicy.Prompt[];
    url?: (ctx: KoaContextWithOIDC, interaction: Interaction) => CanBePromise<string>;
  };

  audiences?: (
    ctx: KoaContextWithOIDC,
    sub: string | undefined,
    token: AccessToken | ClientCredentials,
    use: 'access_token' | 'client_credentials'
  ) => CanBePromise<false | string | string[]>;

  findAccount?: FindAccount;

  whitelistedJWA?: {
    authorizationEncryptionAlgValues?: EncryptionAlgValues[];
    authorizationEncryptionEncValues?: EncryptionEncValues[];
    authorizationSigningAlgValues?: SigningAlgorithm[];
    dPoPSigningAlgValues?: AsymmetricSigningAlgorithm[];
    idTokenEncryptionAlgValues?: EncryptionAlgValues[];
    idTokenEncryptionEncValues?: EncryptionEncValues[];
    idTokenSigningAlgValues?: SigningAlgorithmWithNone[];
    introspectionEncryptionAlgValues?: EncryptionAlgValues[];
    introspectionEncryptionEncValues?: EncryptionEncValues[];
    introspectionEndpointAuthSigningAlgValues?: SigningAlgorithm[];
    introspectionSigningAlgValues?: SigningAlgorithmWithNone[];
    requestObjectEncryptionAlgValues?: EncryptionAlgValues[];
    requestObjectEncryptionEncValues?: EncryptionEncValues[];
    requestObjectSigningAlgValues?: SigningAlgorithmWithNone[];
    revocationEndpointAuthSigningAlgValues?: SigningAlgorithm[];
    tokenEndpointAuthSigningAlgValues?: SigningAlgorithm[];
    userinfoEncryptionAlgValues?: EncryptionAlgValues[];
    userinfoEncryptionEncValues?: EncryptionEncValues[];
    userinfoSigningAlgValues?: SigningAlgorithmWithNone[];
  };
}

export type NoneAlg = 'none';
export type AsymmetricSigningAlgorithm = 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES256K' | 'ES384' | 'ES512' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512';
export type SymmetricSigningAlgorithm = 'HS256' | 'HS384' | 'HS512';
export type SigningAlgorithm = AsymmetricSigningAlgorithm | SymmetricSigningAlgorithm;
export type SigningAlgorithmWithNone = AsymmetricSigningAlgorithm | SymmetricSigningAlgorithm | NoneAlg;
export type EncryptionAlgValues = 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'RSA1_5' | 'ECDH-ES' |
  'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW' | 'A128KW' | 'A192KW' | 'A256KW' |
  'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW' | 'PBES2-HS256+A128KW' | 'PBES2-HS384+A192KW' |
  'PBES2-HS512+A256KW' | 'dir';
export type EncryptionEncValues = 'A128CBC-HS256' |'A128GCM' |'A192CBC-HS384' |'A192GCM' |'A256CBC-HS512' |'A256GCM';

export interface InteractionResults {
  login?: {
    remember?: boolean;
    account: string;
    ts?: number;
    amr?: string[];
    acr?: string;
  };

  consent?: {
    rejectedClaims?: string[] | Set<string>
    rejectedScopes?: string[] | Set<string>
    replace?: boolean;
  };

  meta?: AnyObject;

  [key: string]: any;
}

export class Provider extends events.EventEmitter {
  constructor(issuer: string, configuration?: Configuration);

  readonly issuer: string;
  readonly app: Koa;
  readonly callback: (req: http.IncomingMessage | http2.Http2ServerRequest, res: http.ServerResponse | http2.Http2ServerResponse) => void;

  env?: Koa['env'];
  proxy?: Koa['proxy'];
  subdomainOffset?: number;
  proxyIpHeader?: string;
  maxIpsCount?: number;
  keys?: Koa['keys'];
  listen: Koa['listen'];

  interactionResult(
    req: http.IncomingMessage | http2.Http2ServerRequest,
    res: http.ServerResponse | http2.Http2ServerResponse,
    result: InteractionResults,
    options?: { mergeWithLastSubmission?: boolean }
  ): Promise<string>;

  interactionFinished(
    req: http.IncomingMessage | http2.Http2ServerRequest,
    res: http.ServerResponse | http2.Http2ServerResponse,
    result: InteractionResults,
    options?: { mergeWithLastSubmission?: boolean }
  ): Promise<void>;

  interactionDetails(req: http.IncomingMessage | http2.Http2ServerRequest, res: http.ServerResponse | http2.Http2ServerResponse): Promise<Interaction>;

  setProviderSession(
    req: http.IncomingMessage | http2.Http2ServerRequest,
    res: http.ServerResponse | http2.Http2ServerResponse,
    options: {
      account: string;
      ts?: number;
      remember?: boolean;
      clients?: string[];
      meta?: AnyObject;
    }
  ): Promise<Session>;

  registerGrantType(
    name: string,
    handler: (ctx: KoaContextWithOIDC, next: () => Promise<void>) => CanBePromise<void>,
    params?: string | string[] | Set<string>,
    dupes?: string | string[] | Set<string>
  ): void;
  use: Koa['use'];

  // tslint:disable:unified-signatures
  addListener(event: string, listener: (...args: any[]) => void): this;
  addListener(event: 'access_token.destroyed', listener: (accessToken: AccessToken) => void): this;
  addListener(event: 'access_token.saved', listener: (accessToken: AccessToken) => void): this;
  addListener(event: 'authorization_code.saved', listener: (authorizationCode: AuthorizationCode) => void): this;
  addListener(event: 'authorization_code.destroyed', listener: (authorizationCode: AuthorizationCode) => void): this;
  addListener(event: 'authorization_code.consumed', listener: (authorizationCode: AuthorizationCode) => void): this;
  addListener(event: 'device_code.saved', listener: (deviceCode: DeviceCode) => void): this;
  addListener(event: 'device_code.destroyed', listener: (deviceCode: DeviceCode) => void): this;
  addListener(event: 'device_code.consumed', listener: (deviceCode: DeviceCode) => void): this;
  addListener(event: 'client_credentials.destroyed', listener: (clientCredentials: ClientCredentials) => void): this;
  addListener(event: 'client_credentials.saved', listener: (clientCredentials: ClientCredentials) => void): this;
  addListener(event: 'interaction.destroyed', listener: (interaction: Interaction) => void): this;
  addListener(event: 'interaction.saved', listener: (interaction: Interaction) => void): this;
  addListener(event: 'session.destroyed', listener: (session: Session) => void): this;
  addListener(event: 'session.saved', listener: (session: Session) => void): this;
  addListener(event: 'replay_detection.destroyed', listener: (replayDetection: ReplayDetection) => void): this;
  addListener(event: 'replay_detection.saved', listener: (replayDetection: ReplayDetection) => void): this;
  addListener(event: 'pushed_authorization_request.destroyed', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  addListener(event: 'pushed_authorization_request.saved', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  addListener(event: 'registration_access_token.destroyed', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  addListener(event: 'registration_access_token.saved', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  addListener(event: 'refresh_token.destroyed', listener: (refreshToken: RefreshToken) => void): this;
  addListener(event: 'refresh_token.saved', listener: (refreshToken: RefreshToken) => void): this;
  addListener(event: 'refresh_token.consumed', listener: (refreshToken: RefreshToken) => void): this;
  addListener(event: 'authorization.accepted', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'authorization.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'authorization.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'end_session.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'end_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'grant.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'interaction.ended', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'interaction.started', listener: (ctx: KoaContextWithOIDC, interaction: PromptDetail) => void): this;
  addListener(event: 'grant.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'grant.revoked', listener: (ctx: KoaContextWithOIDC, grantId: string) => void): this;
  addListener(event: 'backchannel.success', listener: (ctx: KoaContextWithOIDC, client: Client, accountId: string, sid: string) => void): this;
  addListener(event: 'backchannel.error', listener: (ctx: KoaContextWithOIDC, err: Error, client: Client, accountId: string, sid: string) => void): this;
  addListener(event: 'pushed_authorization_request.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  addListener(event: 'pushed_authorization_request.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'registration_update.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  addListener(event: 'registration_update.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'registration_delete.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  addListener(event: 'registration_delete.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'registration_create.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  addListener(event: 'registration_create.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'introspection.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'registration_read.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'jwks.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'discovery.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'check_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'check_session_origin.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'userinfo.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'revocation.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  addListener(event: 'server_error', listener: (ctx: KoaContextWithOIDC, err: Error) => void): this;

  on(event: string, listener: (...args: any[]) => void): this;
  on(event: 'access_token.destroyed', listener: (accessToken: AccessToken) => void): this;
  on(event: 'access_token.saved', listener: (accessToken: AccessToken) => void): this;
  on(event: 'authorization_code.saved', listener: (authorizationCode: AuthorizationCode) => void): this;
  on(event: 'authorization_code.destroyed', listener: (authorizationCode: AuthorizationCode) => void): this;
  on(event: 'authorization_code.consumed', listener: (authorizationCode: AuthorizationCode) => void): this;
  on(event: 'device_code.saved', listener: (deviceCode: DeviceCode) => void): this;
  on(event: 'device_code.destroyed', listener: (deviceCode: DeviceCode) => void): this;
  on(event: 'device_code.consumed', listener: (deviceCode: DeviceCode) => void): this;
  on(event: 'client_credentials.destroyed', listener: (clientCredentials: ClientCredentials) => void): this;
  on(event: 'client_credentials.saved', listener: (clientCredentials: ClientCredentials) => void): this;
  on(event: 'interaction.destroyed', listener: (interaction: Interaction) => void): this;
  on(event: 'interaction.saved', listener: (interaction: Interaction) => void): this;
  on(event: 'session.destroyed', listener: (session: Session) => void): this;
  on(event: 'session.saved', listener: (session: Session) => void): this;
  on(event: 'replay_detection.destroyed', listener: (replayDetection: ReplayDetection) => void): this;
  on(event: 'replay_detection.saved', listener: (replayDetection: ReplayDetection) => void): this;
  on(event: 'pushed_authorization_request.destroyed', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  on(event: 'pushed_authorization_request.saved', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  on(event: 'registration_access_token.destroyed', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  on(event: 'registration_access_token.saved', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  on(event: 'refresh_token.destroyed', listener: (refreshToken: RefreshToken) => void): this;
  on(event: 'refresh_token.saved', listener: (refreshToken: RefreshToken) => void): this;
  on(event: 'refresh_token.consumed', listener: (refreshToken: RefreshToken) => void): this;
  on(event: 'authorization.accepted', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'authorization.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'authorization.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'end_session.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'end_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'grant.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'interaction.ended', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'interaction.started', listener: (ctx: KoaContextWithOIDC, interaction: PromptDetail) => void): this;
  on(event: 'grant.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'grant.revoked', listener: (ctx: KoaContextWithOIDC, grantId: string) => void): this;
  on(event: 'backchannel.success', listener: (ctx: KoaContextWithOIDC, client: Client, accountId: string, sid: string) => void): this;
  on(event: 'backchannel.error', listener: (ctx: KoaContextWithOIDC, err: Error, client: Client, accountId: string, sid: string) => void): this;
  on(event: 'pushed_authorization_request.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  on(event: 'pushed_authorization_request.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'registration_update.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  on(event: 'registration_update.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'registration_delete.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  on(event: 'registration_delete.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'registration_create.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  on(event: 'registration_create.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'introspection.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'registration_read.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'jwks.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'discovery.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'check_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'check_session_origin.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'userinfo.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'revocation.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  on(event: 'server_error', listener: (ctx: KoaContextWithOIDC, err: Error) => void): this;

  once(event: string, listener: (...args: any[]) => void): this;
  once(event: 'access_token.destroyed', listener: (accessToken: AccessToken) => void): this;
  once(event: 'access_token.saved', listener: (accessToken: AccessToken) => void): this;
  once(event: 'authorization_code.saved', listener: (authorizationCode: AuthorizationCode) => void): this;
  once(event: 'authorization_code.destroyed', listener: (authorizationCode: AuthorizationCode) => void): this;
  once(event: 'authorization_code.consumed', listener: (authorizationCode: AuthorizationCode) => void): this;
  once(event: 'device_code.saved', listener: (deviceCode: DeviceCode) => void): this;
  once(event: 'device_code.destroyed', listener: (deviceCode: DeviceCode) => void): this;
  once(event: 'device_code.consumed', listener: (deviceCode: DeviceCode) => void): this;
  once(event: 'client_credentials.destroyed', listener: (clientCredentials: ClientCredentials) => void): this;
  once(event: 'client_credentials.saved', listener: (clientCredentials: ClientCredentials) => void): this;
  once(event: 'interaction.destroyed', listener: (interaction: Interaction) => void): this;
  once(event: 'interaction.saved', listener: (interaction: Interaction) => void): this;
  once(event: 'session.destroyed', listener: (session: Session) => void): this;
  once(event: 'session.saved', listener: (session: Session) => void): this;
  once(event: 'replay_detection.destroyed', listener: (replayDetection: ReplayDetection) => void): this;
  once(event: 'replay_detection.saved', listener: (replayDetection: ReplayDetection) => void): this;
  once(event: 'pushed_authorization_request.destroyed', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  once(event: 'pushed_authorization_request.saved', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  once(event: 'registration_access_token.destroyed', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  once(event: 'registration_access_token.saved', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  once(event: 'refresh_token.destroyed', listener: (refreshToken: RefreshToken) => void): this;
  once(event: 'refresh_token.saved', listener: (refreshToken: RefreshToken) => void): this;
  once(event: 'refresh_token.consumed', listener: (refreshToken: RefreshToken) => void): this;
  once(event: 'authorization.accepted', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'authorization.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'authorization.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'end_session.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'end_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'grant.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'interaction.ended', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'interaction.started', listener: (ctx: KoaContextWithOIDC, interaction: PromptDetail) => void): this;
  once(event: 'grant.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'grant.revoked', listener: (ctx: KoaContextWithOIDC, grantId: string) => void): this;
  once(event: 'backchannel.success', listener: (ctx: KoaContextWithOIDC, client: Client, accountId: string, sid: string) => void): this;
  once(event: 'backchannel.error', listener: (ctx: KoaContextWithOIDC, err: Error, client: Client, accountId: string, sid: string) => void): this;
  once(event: 'pushed_authorization_request.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  once(event: 'pushed_authorization_request.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'registration_update.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  once(event: 'registration_update.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'registration_delete.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  once(event: 'registration_delete.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'registration_create.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  once(event: 'registration_create.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'introspection.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'registration_read.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'jwks.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'discovery.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'check_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'check_session_origin.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'userinfo.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'revocation.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  once(event: 'server_error', listener: (ctx: KoaContextWithOIDC, err: Error) => void): this;

  prependListener(event: string, listener: (...args: any[]) => void): this;
  prependListener(event: 'access_token.destroyed', listener: (accessToken: AccessToken) => void): this;
  prependListener(event: 'access_token.saved', listener: (accessToken: AccessToken) => void): this;
  prependListener(event: 'authorization_code.saved', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependListener(event: 'authorization_code.destroyed', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependListener(event: 'authorization_code.consumed', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependListener(event: 'device_code.saved', listener: (deviceCode: DeviceCode) => void): this;
  prependListener(event: 'device_code.destroyed', listener: (deviceCode: DeviceCode) => void): this;
  prependListener(event: 'device_code.consumed', listener: (deviceCode: DeviceCode) => void): this;
  prependListener(event: 'client_credentials.destroyed', listener: (clientCredentials: ClientCredentials) => void): this;
  prependListener(event: 'client_credentials.saved', listener: (clientCredentials: ClientCredentials) => void): this;
  prependListener(event: 'interaction.destroyed', listener: (interaction: Interaction) => void): this;
  prependListener(event: 'interaction.saved', listener: (interaction: Interaction) => void): this;
  prependListener(event: 'session.destroyed', listener: (session: Session) => void): this;
  prependListener(event: 'session.saved', listener: (session: Session) => void): this;
  prependListener(event: 'replay_detection.destroyed', listener: (replayDetection: ReplayDetection) => void): this;
  prependListener(event: 'replay_detection.saved', listener: (replayDetection: ReplayDetection) => void): this;
  prependListener(event: 'pushed_authorization_request.destroyed', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  prependListener(event: 'pushed_authorization_request.saved', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  prependListener(event: 'registration_access_token.destroyed', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  prependListener(event: 'registration_access_token.saved', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  prependListener(event: 'refresh_token.destroyed', listener: (refreshToken: RefreshToken) => void): this;
  prependListener(event: 'refresh_token.saved', listener: (refreshToken: RefreshToken) => void): this;
  prependListener(event: 'refresh_token.consumed', listener: (refreshToken: RefreshToken) => void): this;
  prependListener(event: 'authorization.accepted', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'authorization.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'authorization.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'end_session.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'end_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'grant.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'interaction.ended', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'interaction.started', listener: (ctx: KoaContextWithOIDC, interaction: PromptDetail) => void): this;
  prependListener(event: 'grant.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'grant.revoked', listener: (ctx: KoaContextWithOIDC, grantId: string) => void): this;
  prependListener(event: 'backchannel.success', listener: (ctx: KoaContextWithOIDC, client: Client, accountId: string, sid: string) => void): this;
  prependListener(event: 'backchannel.error', listener: (ctx: KoaContextWithOIDC, err: Error, client: Client, accountId: string, sid: string) => void): this;
  prependListener(event: 'pushed_authorization_request.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependListener(event: 'pushed_authorization_request.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'registration_update.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependListener(event: 'registration_update.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'registration_delete.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependListener(event: 'registration_delete.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'registration_create.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependListener(event: 'registration_create.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'introspection.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'registration_read.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'jwks.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'discovery.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'check_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'check_session_origin.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'userinfo.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'revocation.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependListener(event: 'server_error', listener: (ctx: KoaContextWithOIDC, err: Error) => void): this;

  prependOnceListener(event: string, listener: (...args: any[]) => void): this;
  prependOnceListener(event: 'access_token.destroyed', listener: (accessToken: AccessToken) => void): this;
  prependOnceListener(event: 'access_token.saved', listener: (accessToken: AccessToken) => void): this;
  prependOnceListener(event: 'authorization_code.saved', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependOnceListener(event: 'authorization_code.destroyed', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependOnceListener(event: 'authorization_code.consumed', listener: (authorizationCode: AuthorizationCode) => void): this;
  prependOnceListener(event: 'device_code.saved', listener: (deviceCode: DeviceCode) => void): this;
  prependOnceListener(event: 'device_code.destroyed', listener: (deviceCode: DeviceCode) => void): this;
  prependOnceListener(event: 'device_code.consumed', listener: (deviceCode: DeviceCode) => void): this;
  prependOnceListener(event: 'client_credentials.destroyed', listener: (clientCredentials: ClientCredentials) => void): this;
  prependOnceListener(event: 'client_credentials.saved', listener: (clientCredentials: ClientCredentials) => void): this;
  prependOnceListener(event: 'interaction.destroyed', listener: (interaction: Interaction) => void): this;
  prependOnceListener(event: 'interaction.saved', listener: (interaction: Interaction) => void): this;
  prependOnceListener(event: 'session.destroyed', listener: (session: Session) => void): this;
  prependOnceListener(event: 'session.saved', listener: (session: Session) => void): this;
  prependOnceListener(event: 'replay_detection.destroyed', listener: (replayDetection: ReplayDetection) => void): this;
  prependOnceListener(event: 'replay_detection.saved', listener: (replayDetection: ReplayDetection) => void): this;
  prependOnceListener(event: 'pushed_authorization_request.destroyed', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  prependOnceListener(event: 'pushed_authorization_request.saved', listener: (pushedAuthorizationRequest: PushedAuthorizationRequest) => void): this;
  prependOnceListener(event: 'registration_access_token.destroyed', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  prependOnceListener(event: 'registration_access_token.saved', listener: (registrationAccessToken: RegistrationAccessToken) => void): this;
  prependOnceListener(event: 'refresh_token.destroyed', listener: (refreshToken: RefreshToken) => void): this;
  prependOnceListener(event: 'refresh_token.saved', listener: (refreshToken: RefreshToken) => void): this;
  prependOnceListener(event: 'refresh_token.consumed', listener: (refreshToken: RefreshToken) => void): this;
  prependOnceListener(event: 'authorization.accepted', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'authorization.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'authorization.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'end_session.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'end_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'grant.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'interaction.ended', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'interaction.started', listener: (ctx: KoaContextWithOIDC, interaction: PromptDetail) => void): this;
  prependOnceListener(event: 'grant.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'grant.revoked', listener: (ctx: KoaContextWithOIDC, grantId: string) => void): this;
  prependOnceListener(event: 'backchannel.success', listener: (ctx: KoaContextWithOIDC, client: Client, accountId: string, sid: string) => void): this;
  prependOnceListener(event: 'backchannel.error', listener: (ctx: KoaContextWithOIDC, err: Error, client: Client, accountId: string, sid: string) => void): this;
  prependOnceListener(event: 'pushed_authorization_request.success', listener: (ctx: KoaContextWithOIDC) => void): this;
  prependOnceListener(event: 'pushed_authorization_request.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'registration_update.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependOnceListener(event: 'registration_update.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'registration_delete.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependOnceListener(event: 'registration_delete.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'registration_create.success', listener: (ctx: KoaContextWithOIDC, client: Client) => void): this;
  prependOnceListener(event: 'registration_create.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'introspection.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'registration_read.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'jwks.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'discovery.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'check_session.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'check_session_origin.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'userinfo.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'revocation.error', listener: (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => void): this;
  prependOnceListener(event: 'server_error', listener: (ctx: KoaContextWithOIDC, err: Error) => void): this;
  // tslint:enable:unified-signatures

  readonly Client: typeof Client;
  readonly AccessToken: typeof AccessToken;
  readonly InitialAccessToken: typeof InitialAccessToken;
  readonly RefreshToken: typeof RefreshToken;
  readonly AuthorizationCode: typeof AuthorizationCode;
  readonly RegistrationAccessToken: typeof RegistrationAccessToken;
  readonly PushedAuthorizationRequest: typeof PushedAuthorizationRequest;
  readonly ClientCredentials: typeof ClientCredentials;
  readonly DeviceCode: typeof DeviceCode;
  readonly BaseToken: typeof BaseToken;
  readonly Account: { findAccount: FindAccount; };
  readonly IdToken: typeof IdToken;
  readonly ReplayDetection: typeof ReplayDetection;
  readonly requestUriCache: RequestUriCache;
  readonly OIDCContext: typeof OIDCContext;
  readonly Session: typeof Session;
  readonly Interaction: typeof Interaction;
}

export default Provider;

declare class DefaultPolicy extends Array<interactionPolicy.Prompt> {
  get(name: string): interactionPolicy.Prompt;
  remove(name: string): void;
  clear(): void;
  add(prompt: interactionPolicy.Prompt, index?: number): void;
}

export namespace interactionPolicy {
  class Check {
    constructor(
      reason: string,
      description: string,
      error: string,
      check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>,
      details?: (ctx: KoaContextWithOIDC) => CanBePromise<AnyObject>
    );
    constructor(
      reason: string,
      description: string,
      check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>,
      details?: (ctx: KoaContextWithOIDC) => CanBePromise<AnyObject>
    );

    reason: string;
    description: string;
    error: string;
    details: (ctx: KoaContextWithOIDC) => CanBePromise<AnyObject>;
    check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>;
  }

  class Prompt {
    constructor(info: { name: string, requestable?: boolean }, ...checks: Check[]);
    constructor(info: { name: string, requestable?: boolean }, details: (ctx: KoaContextWithOIDC) => CanBePromise<AnyObject>, ...checks: Check[]);

    name: string;
    requestable: boolean;
    details?: (ctx: KoaContextWithOIDC) => Promise<AnyObject>;
    checks: Check[];
  }

  function base(): DefaultPolicy;
}

export namespace errors {
  class OIDCProviderError extends Error {
    constructor(status: number, message: string);
    error: string;
    error_description?: string;
    error_detail?: string;
    expose: boolean;
    statusCode: number;
    status: number;
  }
  class AccessDenied extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class AuthorizationPending extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class ConsentRequired extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class ExpiredToken extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InteractionRequired extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidClient extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidClientAuth extends OIDCProviderError {
    constructor(detail: string);
  }
  class InvalidClientMetadata extends OIDCProviderError {
    constructor(description: string);
  }
  class InvalidGrant extends OIDCProviderError {
    constructor(detail: string);
  }
  class InvalidRequest extends OIDCProviderError {
    constructor(description: string, code?: number);
  }
  class SessionNotFound extends InvalidRequest {}
  class InvalidRequestObject extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidRequestUri extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidScope extends OIDCProviderError {
    constructor(description: string, scope: string);
  }
  class InvalidSoftwareStatement extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidTarget extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class InvalidToken extends OIDCProviderError {
    constructor(detail: string);
  }
  class LoginRequired extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class RedirectUriMismatch extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class RegistrationNotSupported extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class RequestNotSupported extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class RequestUriNotSupported extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class SlowDown extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class TemporarilyUnavailable extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class UnapprovedSoftwareStatement extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class UnauthorizedClient extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class UnsupportedGrantType extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class UnsupportedResponseMode extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class UnsupportedResponseType extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
  class WebMessageUriMismatch extends OIDCProviderError {
    constructor(description?: string, detail?: string);
  }
}
