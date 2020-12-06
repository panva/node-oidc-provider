/// <reference types="node" />
// TypeScript Version: 3.6

import * as events from 'events';
import * as http from 'http';
import * as http2 from 'http2';
import * as https from 'https';
import * as tls from 'tls';

import * as jose from 'jose';
import * as Koa from 'koa';

export {};

export type CanBePromise<T> = Promise<T> | T;
export type RetryFunction = (retry: number, error: Error) => number;
export type FindAccount = (ctx: KoaContextWithOIDC, sub: string, token?: AuthorizationCode | AccessToken | DeviceCode) => CanBePromise<Account | undefined>;
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
  client_id?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: ResponseType[];

  application_type?: 'web' | 'native';
  client_id_issued_at?: number;
  client_name?: string;
  client_secret_expires_at?: number;
  client_secret?: string;
  client_uri?: string;
  contacts?: string[];
  default_acr_values?: string[];
  default_max_age?: number;
  id_token_signed_response_alg?: SigningAlgorithmWithNone;
  initiate_login_uri?: string;
  jwks_uri?: string;
  jwks?: jose.JSONWebKeySet;
  logo_uri?: string;
  policy_uri?: string;
  post_logout_redirect_uris?: string[];
  require_auth_time?: boolean;
  scope?: string;
  sector_identifier_uri?: string;
  subject_type?: SubjectTypes;
  token_endpoint_auth_method?: ClientAuthMethod;
  tos_uri?: string;

  tls_client_auth_subject_dn?: string;
  tls_client_auth_san_dns?: string;
  tls_client_auth_san_uri?: string;
  tls_client_auth_san_ip?: string;
  tls_client_auth_san_email?: string;
  token_endpoint_auth_signing_alg?: SigningAlgorithm;
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
  request_object_signing_alg?: SigningAlgorithmWithNone;
  request_object_encryption_alg?: EncryptionAlgValues;
  request_object_encryption_enc?: EncryptionEncValues;
  request_uris?: string[];
  id_token_encrypted_response_alg?: EncryptionAlgValues;
  id_token_encrypted_response_enc?: EncryptionEncValues;
  userinfo_encrypted_response_alg?: EncryptionAlgValues;
  userinfo_encrypted_response_enc?: EncryptionEncValues;
  authorization_signed_response_alg?: SigningAlgorithm;
  authorization_encrypted_response_alg?: EncryptionAlgValues;
  authorization_encrypted_response_enc?: EncryptionEncValues;
  web_message_uris?: string[];
  tls_client_certificate_bound_access_tokens?: boolean;

  require_signed_request_object?: boolean;
  require_pushed_authorization_requests?: boolean;

  [key: string]: any;
}

export interface ClientMetadata extends AnyClientMetadata {
  client_id: string;
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
  result?: InteractionResults;
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
  metaFor(clientId: string, value: AnyObject): void;
  acceptedScopesFor(clientId: string): Set<string>;
  acceptedClaimsFor(clientId: string): Set<string>;
  promptedScopesFor(clientId: string): Set<string>;
  promptedScopesFor(clientId: string, scopes: string[] | Set<string>): void;
  promptedClaimsFor(clientId: string): Set<string>;
  promptedClaimsFor(clientId: string, claims: string[] | Set<string>): void;
  rejectedScopesFor(clientId: string): Set<string>;
  rejectedScopesFor(clientId: string, scopes: string[] | Set<string>, replace?: boolean): void;
  rejectedClaimsFor(clientId: string): Set<string>;
  rejectedClaimsFor(clientId: string, claims: string[] | Set<string>, replace?: boolean): void;

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

  static revokeByGrantId(grantId: string): Promise<void>;
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

  static revokeByGrantId(grantId: string): Promise<void>;
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

  static revokeByGrantId(grantId: string): Promise<void>;
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

  static revokeByGrantId(grantId: string): Promise<void>;
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
  static validate(idToken: string, client: Client): Promise<{ header: AnyObject, payload: AnyObject }>;
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

export interface AdapterPayload extends AnyClientMetadata {
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

export type AdapterFactory = (name: string) => Adapter;

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

  adapter?: AdapterConstructor | AdapterFactory;

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
      allowedPolicy?: (ctx: KoaContextWithOIDC, client: Client, token: AccessToken | ClientCredentials | RefreshToken) => CanBePromise<boolean>;
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
      requireSignedRequestObject?: boolean;
      mergingStrategy?: {
        name?: 'lax' | 'strict' | 'whitelist',
        whitelist?: string[] | Set<string>;
      };
    };

    dPoP?: {
      enabled?: boolean,
      iatTolerance?: number,
      ack?: 'draft-01'
    },

    sessionManagement?: {
      enabled?: boolean,
      keepHeaders?: boolean,
      ack?: 28 | 'draft-28' | 'draft-29' | 'draft-30',
      scriptNonce?: (ctx: KoaContextWithOIDC) => string
    },

    backchannelLogout?: {
      enabled?: boolean,
      ack?: 4 | 'draft-04' | 'draft-05' | 'draft-06'
    },

    ietfJWTAccessTokenProfile?: {
      enabled?: boolean,
      ack?: 2 | 'draft-02' | 'draft-03' | 'draft-04' | 'draft-05'
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
      ack?: 'draft-09'
    },

    jwtResponseModes?: {
      enabled?: boolean,
      ack?: 1 | 2 | 'draft-02'
    },

    pushedAuthorizationRequests?: {
      requirePushedAuthorizationRequests?: boolean;
      enabled?: boolean,
      ack?: 'draft-02' | 'draft-03'
    },

    rpInitiatedLogout?: {
      enabled?: boolean,
      postLogoutSuccessSource?: (ctx: KoaContextWithOIDC) => CanBePromise<void | undefined>,
      logoutSource?: (ctx: KoaContextWithOIDC, form: string) => CanBePromise<void | undefined>
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
      ack?: 2 | 'draft-02' | 'draft-03' | 'draft-04';
      logoutPendingSource?: (ctx: KoaContextWithOIDC, frames: string[], postLogoutRedirectUri?: string) => CanBePromise<void | undefined>;
    };
  };

  extraAccessTokenClaims?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials) => CanBePromise<AnyObject | void | undefined> ;

  formats?: {
    AccessToken?: AccessTokenFormatFunction | TokenFormat;
    ClientCredentials?: ClientCredentialsFormatFunction | TokenFormat;
    jwtAccessTokenSigningAlg?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, client: Client) => CanBePromise<AsymmetricSigningAlgorithm>;
    customizers?: {
      jwt?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: JWTStructured) => CanBePromise<JWTStructured>;
      'jwt-ietf'?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: JWTStructured) => CanBePromise<JWTStructured>;
      paseto?: (ctx: KoaContextWithOIDC, token: AccessToken | ClientCredentials, parts: PASETOStructured) => CanBePromise<PASETOStructured>;
    };
  };

  httpOptions?: (options: HttpRequestOptions) => HttpRequestOptions;

  expiresWithSession?: (ctx: KoaContextWithOIDC, token: AccessToken | AuthorizationCode | DeviceCode) => CanBePromise<boolean>;

  issueRefreshToken?: (ctx: KoaContextWithOIDC, client: Client, code: AuthorizationCode | DeviceCode) => CanBePromise<boolean>;

  jwks?: jose.JSONWebKeySet;

  responseTypes?: ResponseType[];

  pkceMethods?: PKCEMethods[];

  pkce?: {
    methods: PKCEMethods[];
    required?: (ctx: KoaContextWithOIDC, client: Client) => boolean;
  };

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

declare class Checks extends Array<interactionPolicy.Check> {
  get(name: string): interactionPolicy.Check | undefined;
  remove(name: string): void;
  clear(): void;
  add(prompt: interactionPolicy.Check, index?: number): void;
}

export namespace interactionPolicy {
  interface DefaultPolicy extends Array<interactionPolicy.Prompt> {
    get(name: string): interactionPolicy.Prompt | undefined;
    remove(name: string): void;
    clear(): void;
    add(prompt: interactionPolicy.Prompt, index?: number): void;
  }

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
    checks: Checks;
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
  class InvalidDpopProof extends OIDCProviderError {
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
