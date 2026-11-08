/**
 * Canonical provider-owned template for the complete public declarations.
 *
 * This source-only template preserves the declaration imports, exports, models, and
 * supporting types. The declaration generator assembles each @generate directive
 * from its canonical source before the complete file is handed off to DefinitelyTyped.
 */

import * as crypto from "node:crypto";
import * as dns from "node:dns";
import * as http from "node:http";
import * as http2 from "node:http2";
import * as https from "node:https";

import KeyGrip = require("keygrip");
import Koa = require("koa");

export {};

export type CanBePromise<T> = Promise<T> | T;

export interface UnknownObject {
    [key: string]: unknown;
}

export interface JWK {
    kid?: string | undefined;
    x5c?: readonly string[] | undefined;
    alg?: string | undefined;
    crv?: string | undefined;
    d?: string | undefined;
    dp?: string | undefined;
    dq?: string | undefined;
    e?: string | undefined;
    ext?: boolean | undefined;
    k?: string | undefined;
    key_ops?: readonly string[] | undefined;
    kty?: string | undefined;
    n?: string | undefined;
    p?: string | undefined;
    q?: string | undefined;
    qi?: string | undefined;
    use?: string | undefined;
    pub?: string | undefined;
    priv?: string | undefined;
    x?: string | undefined;
    y?: string | undefined;
}

export interface JWKS {
    keys: ReadonlyArray<JWK | ExternalSigningKey>;
}

export interface AllClientMetadata {
    client_id?: string | undefined;
    redirect_uris?: readonly string[] | undefined;
    grant_types?: readonly string[] | undefined;
    response_types?: readonly ResponseType[] | undefined;
    response_modes?: readonly string[] | undefined;

    application_type?: "web" | "native" | undefined;
    client_id_issued_at?: number | undefined;
    client_name?: string | undefined;
    client_secret_expires_at?: number | undefined;
    client_secret?: string | undefined;
    client_uri?: string | undefined;
    contacts?: readonly string[] | undefined;
    default_acr_values?: readonly string[] | undefined;
    default_max_age?: number | undefined;
    id_token_signed_response_alg?: SigningAlgorithmWithNone | undefined;
    initiate_login_uri?: string | undefined;
    jwks_uri?: string | undefined;
    jwks?: JWKS | undefined;
    logo_uri?: string | undefined;
    policy_uri?: string | undefined;
    post_logout_redirect_uris?: readonly string[] | undefined;
    require_auth_time?: boolean | undefined;
    scope?: string | undefined;
    sector_identifier_uri?: string | undefined;
    subject_type?: SubjectTypes | undefined;
    token_endpoint_auth_method?: ClientAuthMethod | undefined;
    tos_uri?: string | undefined;

    tls_client_auth_subject_dn?: string | undefined;
    tls_client_auth_san_dns?: string | undefined;
    tls_client_auth_san_uri?: string | undefined;
    tls_client_auth_san_ip?: string | undefined;
    tls_client_auth_san_email?: string | undefined;
    token_endpoint_auth_signing_alg?: SigningAlgorithm | undefined;
    userinfo_signed_response_alg?: SigningAlgorithmWithNone | undefined;
    introspection_signed_response_alg?: SigningAlgorithmWithNone | undefined;
    introspection_encrypted_response_alg?: EncryptionAlgValues | undefined;
    introspection_encrypted_response_enc?: EncryptionEncValues | undefined;
    backchannel_logout_session_required?: boolean | undefined;
    backchannel_logout_uri?: string | undefined;
    request_object_signing_alg?: SigningAlgorithmWithNone | undefined;
    request_object_encryption_alg?: EncryptionAlgValues | undefined;
    request_object_encryption_enc?: EncryptionEncValues | undefined;
    id_token_encrypted_response_alg?: EncryptionAlgValues | undefined;
    id_token_encrypted_response_enc?: EncryptionEncValues | undefined;
    userinfo_encrypted_response_alg?: EncryptionAlgValues | undefined;
    userinfo_encrypted_response_enc?: EncryptionEncValues | undefined;
    authorization_signed_response_alg?: SigningAlgorithm | undefined;
    authorization_encrypted_response_alg?: EncryptionAlgValues | undefined;
    authorization_encrypted_response_enc?: EncryptionEncValues | undefined;
    tls_client_certificate_bound_access_tokens?: boolean | undefined;
    use_mtls_endpoint_aliases?: boolean | undefined;
    dpop_bound_access_tokens?: boolean | undefined;
    authorization_details_types?: readonly string[] | undefined;

    require_signed_request_object?: boolean | undefined;
    require_pushed_authorization_requests?: boolean | undefined;

    backchannel_user_code_parameter?: boolean | undefined;
    backchannel_authentication_request_signing_alg?: string | undefined;
    backchannel_client_notification_endpoint?: string | undefined;
    backchannel_token_delivery_mode?: CIBADeliveryMode | undefined;

    authorization_encryption_alg_values_supported?: readonly EncryptionAlgValues[] | undefined;
    authorization_encryption_enc_values_supported?: readonly EncryptionEncValues[] | undefined;
    authorization_signing_alg_values_supported?: readonly SigningAlgorithm[] | undefined;
    backchannel_authentication_request_signing_alg_values_supported?: readonly SigningAlgorithm[] | undefined;
    id_token_encryption_alg_values_supported?: readonly EncryptionAlgValues[] | undefined;
    id_token_encryption_enc_values_supported?: readonly EncryptionEncValues[] | undefined;
    id_token_signing_alg_values_supported?: readonly SigningAlgorithmWithNone[] | undefined;
    introspection_encryption_alg_values_supported?: readonly EncryptionAlgValues[] | undefined;
    introspection_encryption_enc_values_supported?: readonly EncryptionEncValues[] | undefined;
    introspection_signing_alg_values_supported?: readonly SigningAlgorithmWithNone[] | undefined;
    request_object_encryption_alg_values_supported?: readonly EncryptionAlgValues[] | undefined;
    request_object_encryption_enc_values_supported?: readonly EncryptionEncValues[] | undefined;
    request_object_signing_alg_values_supported?: readonly SigningAlgorithmWithNone[] | undefined;
    subject_types_supported?: readonly SubjectTypes[] | undefined;
    token_endpoint_auth_methods_supported?: readonly ClientAuthMethod[] | undefined;
    token_endpoint_auth_signing_alg_values_supported?: readonly SigningAlgorithm[] | undefined;
    userinfo_encryption_alg_values_supported?: readonly EncryptionAlgValues[] | undefined;
    userinfo_encryption_enc_values_supported?: readonly EncryptionEncValues[] | undefined;
    userinfo_signing_alg_values_supported?: readonly SigningAlgorithmWithNone[] | undefined;

    [key: string]: unknown;
}

export interface ClientMetadata extends AllClientMetadata {
    client_id: string;
}

export type ResponseType =
    | "code"
    | "id_token"
    | "code id_token"
    | "id_token token"
    | "code token"
    | "code id_token token"
    | "none";
export type CIBADeliveryMode = "poll" | "ping";
export type SubjectTypes = "public" | "pairwise";
// @generate clientAuthMethods

export interface ClaimsParameterMember {
    essential?: boolean | undefined;
    value?: string | undefined;
    values?: readonly string[] | undefined;

    [key: string]: unknown;
}

export interface ClaimsParameter {
    id_token?:
        | {
            [key: string]: null | ClaimsParameterMember;
        }
        | undefined;
    userinfo?:
        | {
            [key: string]: null | ClaimsParameterMember;
        }
        | undefined;
}

export interface ClientAuthorizationState {
    persistsLogout?: boolean | undefined;
    sid?: string | undefined;
    grantId?: string | undefined;
}

export interface PromptDetail {
    name: "login" | "consent" | string;
    reasons: string[];
    details: UnknownObject;
}

declare class Interaction extends BaseModel {
    readonly kind: "Interaction";
    iat: number;
    exp: number;
    session?:
        | {
            accountId: string;
            uid: string;
            cookie: string;
            acr?: string | undefined;
            amr?: string[] | undefined;
        }
        | undefined;
    params: UnknownObject;
    prompt: PromptDetail;
    result?: InteractionResults | undefined;
    returnTo: string;
    deviceCode?: string | undefined;
    trusted?: string[] | undefined;
    uid: string;
    lastSubmission?: InteractionResults | undefined;
    grantId?: string | undefined;
    cid: string;

    save(ttl: number): Promise<string>;
    persist(): Promise<string>;
}

declare class Session extends BaseModel {
    readonly kind: "Session";
    iat: number;
    exp: number;
    uid: string;
    jti: string;

    accountId?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    loginTs?: number | undefined;
    transient?: boolean | undefined;
    state?: UnknownObject | undefined;
    authorizations?:
        | {
            [clientId: string]: ClientAuthorizationState;
        }
        | undefined;

    authTime(): number | undefined;
    past(age: number): boolean;

    ensureClientContainer(clientId: string): void;
    loginAccount(details: {
        accountId: string;
        acr?: string | undefined;
        amr?: string[] | undefined;
        loginTs?: number | undefined;
        transient?: boolean | undefined;
    }): void;
    authorizationFor(clientId: string): ClientAuthorizationState;
    sidFor(clientId: string): string | undefined;
    sidFor(clientId: string, value: string): void;
    grantIdFor(clientId: string): string | undefined;
    grantIdFor(clientId: string, value: string): void;

    save(ttl: number): Promise<string>;
    persist(): Promise<string>;
    destroy(): Promise<void>;
    resetIdentifier(): void;
    static find<T>(this: { new(...args: any[]): T }, cookieId: string): Promise<T | undefined>;
    static findByUid(uid: string): Promise<Session | undefined>;
    static get(ctx: Koa.Context): Promise<Session>;
}

declare class Grant extends BaseToken {
    constructor(properties?: {
        clientId?: string | undefined;
        accountId?: string | undefined;
        rar?: AuthorizationDetail[] | undefined;
    });

    accountId?: string | undefined;
    clientId?: string | undefined;
    openid?:
        | {
            scope?: string | undefined;
            claims?: string[] | undefined;
        }
        | undefined;
    resources?:
        | {
            [resource: string]: string;
        }
        | undefined;
    rar?: AuthorizationDetail[] | undefined;
    rejected?: Pick<Grant, "openid" | "resources"> | undefined;

    addOIDCScope(scope: string | string[] | Set<string>): undefined;
    rejectOIDCScope(scope: string | string[] | Set<string>): undefined;
    getOIDCScope(): string;
    getRejectedOIDCScope(): string;
    getOIDCScopeEncountered(): string;
    getOIDCScopeFiltered(filter: string[] | Set<string>): string;

    addOIDCClaims(claims: string[] | Set<string>): undefined;
    rejectOIDCClaims(claims: string[] | Set<string>): undefined;
    getOIDCClaims(): string[];
    getRejectedOIDCClaims(): string[];
    getOIDCClaimsEncountered(): string[];
    getOIDCClaimsFiltered(filter: string[] | Set<string>): string[];

    addResourceScope(resource: string, scope: string | string[] | Set<string>): undefined;
    rejectResourceScope(resource: string, scope: string | string[] | Set<string>): undefined;
    getResourceScope(resource: string): string;
    getRejectedResourceScope(resource: string): string;
    getResourceScopeEncountered(resource: string): string;
    getResourceScopeFiltered(resource: string, filter: string[] | Set<string>): string;

    addRar(detail: AuthorizationDetail): undefined;
}

interface BaseModel {
    jti: string;
    kind: string;
    iat?: number | undefined;
    exp?: number | undefined;
}

declare class BaseModel {
    readonly adapter: Adapter;

    save(ttl?: number): Promise<string>;
    destroy(): Promise<void>;
    emit(eventName: string): void;
    ttlPercentagePassed(): number;

    readonly isValid: boolean;
    readonly isExpired: boolean;
    readonly remainingTTL: number;

    static readonly adapter: Adapter;

    static IN_PAYLOAD: string[];

    static find<T>(this: { new(...args: any[]): T }, id: string, options?: object): Promise<T | undefined>;
}

declare class BaseToken extends BaseModel {
    iat: number;
    exp?: number | undefined;
    jti: string;
    readonly kind: string;
    clientId?: string | undefined;
    client?: Client | undefined;
    readonly format?: string | undefined;
    readonly scopes: Set<string>;
    readonly resourceIndicators: Set<string | undefined>;

    ttlPercentagePassed(): number;

    readonly isValid: boolean;
    readonly isExpired: boolean;
    readonly remainingTTL: number;
    readonly expiration: number;

    static IN_PAYLOAD: string[];

    static find<T>(
        this: { new(...args: any[]): T },
        jti: string,
        options?: { ignoreExpiration?: boolean | undefined },
    ): Promise<T | undefined>;
    save(): Promise<string>;

    readonly adapter: Adapter;
    static readonly adapter: Adapter;
}

declare class ReplayDetection extends BaseModel {
    readonly kind: "ReplayDetection";
    iss?: string | undefined;
    static unique(iss: string, jti: string, exp: number): Promise<boolean>;
}

declare class PushedAuthorizationRequest extends BaseModel {
    constructor(properties: {
        request: string;
        attestationJkt?: string | undefined;
        dpopJkt?: string | undefined;
        trusted?: string[] | undefined;
    });
    readonly kind: "PushedAuthorizationRequest";
    request: string;
    attestationJkt?: string | undefined;
    dpopJkt?: string | undefined;
    trusted?: string[] | undefined;
    consumed: unknown;

    consume(): Promise<void>;
}

declare class RefreshToken extends BaseToken {
    constructor(properties: {
        client: Client;
        accountId: string;
        acr?: string | undefined;
        amr?: string[] | undefined;
        authTime?: number | undefined;
        claims?: ClaimsParameter | undefined;
        nonce?: string | undefined;
        resource?: string | string[] | undefined;
        scope: string;
        sid?: string | undefined;
        sessionUid?: string | undefined;
        expiresWithSession?: boolean | undefined;
        "x5t#S256"?: string | undefined;
        jkt?: string | undefined;
        grantId: string;
        gty: string;
        rar?: AuthorizationDetail[] | undefined;
        [key: string]: unknown;
    });
    readonly kind: "RefreshToken";
    rotations?: number | undefined;
    iiat?: number | undefined;
    accountId: string;
    acr?: string | undefined;
    amr?: string[] | undefined;
    authTime?: number | undefined;
    claims?: ClaimsParameter | undefined;
    nonce?: string | undefined;
    resource?: string | string[] | undefined;
    scope?: string | undefined;
    sid?: string | undefined;
    sessionUid?: string | undefined;
    expiresWithSession?: boolean | undefined;
    "x5t#S256"?: string | undefined;
    jkt?: string | undefined;
    grantId?: string | undefined;
    gty?: string | undefined;
    rar?: AuthorizationDetail[] | undefined;
    attestationJkt?: string | undefined;
    consumed: unknown;

    totalLifetime(): number;
    isSenderConstrained(): boolean;
    consume(): Promise<void>;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class AuthorizationCode extends BaseToken {
    constructor(properties: {
        client: Client;
        accountId: string;
        redirectUri?: string | undefined;
        acr?: string | undefined;
        amr?: string[] | undefined;
        authTime?: number | undefined;
        claims?: ClaimsParameter | undefined;
        nonce?: string | undefined;
        resource?: string | string[] | undefined;
        codeChallenge?: string | undefined;
        codeChallengeMethod?: string | undefined;
        scope: string;
        sid?: string | undefined;
        sessionUid?: string | undefined;
        expiresWithSession?: boolean | undefined;
        "x5t#S256"?: string | undefined;
        dpopJkt?: string | undefined;
        grantId: string;
        gty: string;
        rar?: AuthorizationDetail[] | undefined;
        [key: string]: unknown;
    });
    readonly kind: "AuthorizationCode";
    redirectUri?: string | undefined;
    codeChallenge?: string | undefined;
    codeChallengeMethod?: string | undefined;
    accountId?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    authTime?: number | undefined;
    claims?: ClaimsParameter | undefined;
    nonce?: string | undefined;
    resource?: string | string[] | undefined;
    scope?: string | undefined;
    sid?: string | undefined;
    sessionUid?: string | undefined;
    expiresWithSession?: boolean | undefined;
    "x5t#S256"?: string | undefined;
    dpopJkt?: string | undefined;
    grantId?: string | undefined;
    gty?: string | undefined;
    rar?: AuthorizationDetail[] | undefined;
    attestationJkt?: string | undefined;

    consume(): Promise<void>;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class DeviceCode extends BaseToken {
    constructor(properties: {
        params: UnknownObject;
        userCode: string;
        grantId: string;
        client: Client;
        deviceInfo: UnknownObject;
        rar?: AuthorizationDetail[] | undefined;
        [key: string]: unknown;
    });

    static findByUserCode(
        userCode: string,
        options?: { ignoreExpiration?: boolean | undefined },
    ): Promise<DeviceCode | undefined>;

    readonly kind: "DeviceCode";
    error?: string | undefined;
    errorDescription?: string | undefined;
    params?: UnknownObject | undefined;
    userCode: string;
    inFlight?: boolean | undefined;
    deviceInfo?: UnknownObject | undefined;
    accountId?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    authTime?: number | undefined;
    claims?: ClaimsParameter | undefined;
    nonce?: string | undefined;
    resource?: string | string[] | undefined;
    scope?: string | undefined;
    sid?: string | undefined;
    sessionUid?: string | undefined;
    expiresWithSession?: boolean | undefined;
    grantId: string;
    rar?: AuthorizationDetail[] | undefined;
    attestationJkt?: string | undefined;
    consumed: unknown;

    consume(): Promise<void>;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class BackchannelAuthenticationRequest extends BaseToken {
    constructor(properties?: { clientId?: string | undefined; accountId?: string | undefined });

    readonly kind: "BackchannelAuthenticationRequest";
    error?: string | undefined;
    errorDescription?: string | undefined;
    params?: UnknownObject | undefined;
    accountId?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    authTime?: number | undefined;
    claims?: ClaimsParameter | undefined;
    nonce?: string | undefined;
    resource?: string | string[] | undefined;
    scope?: string | undefined;
    sid?: string | undefined;
    sessionUid?: string | undefined;
    expiresWithSession?: boolean | undefined;
    grantId: string;
    rar?: AuthorizationDetail[] | undefined;
    attestationJkt?: string | undefined;
    consumed: unknown;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class PreAuthorizedCode extends BaseToken {
    constructor(properties: {
        accountId: string;
        clientId: string;
        grantId: string;
        claims?: ClaimsParameter | undefined;
        rar?: AuthorizationDetail[] | undefined;
        resource?: string | string[] | undefined;
        scope: string;
        txCode?: string | undefined;
        [key: string]: unknown;
    });

    readonly kind: "PreAuthorizedCode";
    accountId: string;
    grantId: string;
    claims?: ClaimsParameter | undefined;
    rar?: AuthorizationDetail[] | undefined;
    resource?: string | string[] | undefined;
    scope: string;
    txCode?: string | undefined;
    consumed: unknown;

    consume(): Promise<void>;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class ClientCredentials extends BaseToken {
    constructor(properties: {
        client: Client;
        resourceServer?: ResourceServerInstance | undefined;
        aud?: string | string[] | undefined;
        scope?: string | undefined;
        rar?: AuthorizationDetail[] | undefined;
        [key: string]: unknown;
    });
    readonly kind: "ClientCredentials";
    scope?: string | undefined;
    extra?: UnknownObject | undefined;
    aud?: string | string[] | undefined;
    readonly tokenType: string;
    "x5t#S256"?: string | undefined;
    jkt?: string | undefined;
    resourceServer?: ResourceServerInstance | undefined;
    rar?: AuthorizationDetail[] | undefined;

    setAudience(audience: string | string[]): void;
    setThumbprint(prop: "x5t", input: string | crypto.X509Certificate): void;
    setThumbprint(prop: "jkt", input: string): void;
    isSenderConstrained(): boolean;
}

declare class InitialAccessToken extends BaseToken {
    constructor(properties?: {
        expiresIn?: number | undefined;
        policies?: string[] | undefined;
        [key: string]: unknown;
    });
    readonly kind: "InitialAccessToken";
    clientId: undefined;
    policies?: string[] | undefined;
}

declare class RegistrationAccessToken extends BaseToken {
    readonly kind: "RegistrationAccessToken";
    policies?: string[] | undefined;
}

declare class AccessToken extends BaseToken {
    constructor(properties: {
        client: Client;
        accountId: string;
        resourceServer?: ResourceServerInstance | undefined;
        claims?: ClaimsParameter | undefined;
        aud?: string | string[] | undefined;
        scope?: string | undefined;
        sid?: string | undefined;
        sessionUid?: string | undefined;
        expiresWithSession?: boolean | undefined;
        "x5t#S256"?: string | undefined;
        jkt?: string | undefined;
        grantId: string;
        gty: string;
        rar?: AuthorizationDetail[] | undefined;
        [key: string]: unknown;
    });
    readonly kind: "AccessToken";
    accountId: string;
    resourceServer?: ResourceServerInstance | undefined;
    aud?: string | string[] | undefined;
    claims?: ClaimsParameter | undefined;
    extra?: UnknownObject | undefined;
    grantId: string;
    scope?: string | undefined;
    gty: string;
    rar?: AuthorizationDetail[] | undefined;
    sid?: string | undefined;
    sessionUid?: string | undefined;
    expiresWithSession?: boolean | undefined;
    readonly tokenType: string;
    "x5t#S256"?: string | undefined;
    jkt?: string | undefined;

    setAudience(audience: string | string[]): void;
    setThumbprint(prop: "x5t", input: string | crypto.X509Certificate): void;
    setThumbprint(prop: "jkt", input: string): void;
    isSenderConstrained(): boolean;

    static revokeByGrantId(grantId: string): Promise<void>;
}

declare class IdToken {
    constructor(claims: UnknownObject, context?: { ctx?: KoaContextWithOIDC | undefined; client?: Client | undefined });

    readonly ctx: KoaContextWithOIDC;
    readonly client: Client;
    readonly available: UnknownObject;
    readonly extra: UnknownObject;

    set(key: string, value: any): void;
    payload(): Promise<UnknownObject>;
    issue(context: {
        use: "idtoken" | "logout" | "userinfo" | "introspection" | "authorization";
        expiresAt?: number | undefined;
    }): Promise<string>;
    static validate(idToken: string, client: Client): Promise<{ header: UnknownObject; payload: UnknownObject }>;
}

declare class Claims {
    constructor(
        available: UnknownObject,
        context:
            | { ctx: KoaContextWithOIDC; client?: Client | undefined }
            | { ctx?: undefined; client: Client },
    );

    scope(value?: string): this;
    mask(value: UnknownObject): void;
    rejected(value?: readonly string[]): void;
    result(): Promise<UnknownObject>;
}

declare class Client {
    responseTypeAllowed(type: ResponseType): boolean;
    responseModeAllowed(type: string, responseType: ResponseType, fapiProfile: FapiProfile | undefined): boolean;
    grantTypeAllowed(type: string): boolean;
    redirectUriAllowed(redirectUri: string): boolean;
    postLogoutRedirectUriAllowed(postLogoutRedirectUri: string): boolean;
    includeSid(): boolean;
    compareClientSecret(actual: string): CanBePromise<boolean>;

    metadata(): ClientMetadata;

    backchannelPing(request: BackchannelAuthenticationRequest): Promise<void>;

    readonly clientId: string;

    readonly grantTypes?: readonly string[] | undefined;
    readonly redirectUris?: readonly string[] | undefined;
    readonly responseTypes?: readonly ResponseType[] | undefined;
    readonly responseModes?: readonly string[] | undefined;

    readonly applicationType?: "web" | "native" | undefined;
    readonly clientIdIssuedAt?: number | undefined;
    readonly clientName?: string | undefined;
    readonly clientSecretExpiresAt?: number | undefined;
    readonly clientSecret?: string | undefined;
    readonly clientUri?: string | undefined;
    readonly contacts?: readonly string[] | undefined;
    readonly defaultAcrValues?: readonly string[] | undefined;
    readonly defaultMaxAge?: number | undefined;
    readonly idTokenSignedResponseAlg?: string | undefined;
    readonly initiateLoginUri?: string | undefined;
    readonly jwksUri?: string | undefined;
    readonly jwks?: JWKS | undefined;
    readonly logoUri?: string | undefined;
    readonly policyUri?: string | undefined;
    readonly postLogoutRedirectUris?: readonly string[] | undefined;
    readonly requireAuthTime?: boolean | undefined;
    readonly scope?: string | undefined;
    readonly sectorIdentifierUri?: string | undefined;
    readonly subjectType?: SubjectTypes | undefined;
    readonly clientAuthMethod?: string | undefined;
    readonly tokenEndpointAuthMethod?: string | undefined;
    readonly tosUri?: string | undefined;

    readonly tlsClientAuthSubjectDn?: string | undefined;
    readonly tlsClientAuthSanDns?: string | undefined;
    readonly tlsClientAuthSanUri?: string | undefined;
    readonly tlsClientAuthSanIp?: string | undefined;
    readonly tlsClientAuthSanEmail?: string | undefined;
    readonly tokenEndpointAuthSigningAlg?: string | undefined;
    readonly clientAuthSigningAlg?: string | undefined;
    readonly userinfoSignedResponseAlg?: string | undefined;
    readonly introspectionSignedResponseAlg?: string | undefined;
    readonly introspectionEncryptedResponseAlg?: string | undefined;
    readonly introspectionEncryptedResponseEnc?: string | undefined;
    readonly backchannelLogoutSessionRequired?: boolean | undefined;
    readonly backchannelLogoutUri?: string | undefined;
    readonly requestObjectSigningAlg?: string | undefined;
    readonly requestObjectEncryptionAlg?: string | undefined;
    readonly requestObjectEncryptionEnc?: string | undefined;
    readonly idTokenEncryptedResponseAlg?: string | undefined;
    readonly idTokenEncryptedResponseEnc?: string | undefined;
    readonly userinfoEncryptedResponseAlg?: string | undefined;
    readonly userinfoEncryptedResponseEnc?: string | undefined;
    readonly authorizationSignedResponseAlg?: string | undefined;
    readonly authorizationEncryptedResponseAlg?: string | undefined;
    readonly authorizationEncryptedResponseEnc?: string | undefined;
    readonly tlsClientCertificateBoundAccessTokens?: boolean | undefined;
    readonly useMtlsEndpointAliases?: boolean | undefined;
    readonly dpopBoundAccessTokens?: boolean | undefined;
    readonly authorizationDetailsTypes?: readonly string[] | undefined;
    readonly requireSignedRequestObject?: boolean | undefined;
    readonly requirePushedAuthorizationRequests?: boolean | undefined;

    readonly backchannelUserCodeParameter?: boolean | undefined;
    readonly backchannelAuthenticationRequestSigningAlg?: string | undefined;
    readonly backchannelClientNotificationEndpoint?: string | undefined;
    readonly backchannelTokenDeliveryMode?: CIBADeliveryMode | undefined;

    readonly authorizationEncryptionAlgValuesSupported?: readonly EncryptionAlgValues[] | undefined;
    readonly authorizationEncryptionEncValuesSupported?: readonly EncryptionEncValues[] | undefined;
    readonly authorizationSigningAlgValuesSupported?: readonly SigningAlgorithm[] | undefined;
    readonly backchannelAuthenticationRequestSigningAlgValuesSupported?: readonly SigningAlgorithm[] | undefined;
    readonly idTokenEncryptionAlgValuesSupported?: readonly EncryptionAlgValues[] | undefined;
    readonly idTokenEncryptionEncValuesSupported?: readonly EncryptionEncValues[] | undefined;
    readonly idTokenSigningAlgValuesSupported?: readonly SigningAlgorithmWithNone[] | undefined;
    readonly introspectionEncryptionAlgValuesSupported?: readonly EncryptionAlgValues[] | undefined;
    readonly introspectionEncryptionEncValuesSupported?: readonly EncryptionEncValues[] | undefined;
    readonly introspectionSigningAlgValuesSupported?: readonly SigningAlgorithmWithNone[] | undefined;
    readonly requestObjectEncryptionAlgValuesSupported?: readonly EncryptionAlgValues[] | undefined;
    readonly requestObjectEncryptionEncValuesSupported?: readonly EncryptionEncValues[] | undefined;
    readonly requestObjectSigningAlgValuesSupported?: readonly SigningAlgorithmWithNone[] | undefined;
    readonly subjectTypesSupported?: readonly SubjectTypes[] | undefined;
    readonly tokenEndpointAuthMethodsSupported?: readonly ClientAuthMethod[] | undefined;
    readonly tokenEndpointAuthSigningAlgValuesSupported?: readonly SigningAlgorithm[] | undefined;
    readonly userinfoEncryptionAlgValuesSupported?: readonly EncryptionAlgValues[] | undefined;
    readonly userinfoEncryptionEncValuesSupported?: readonly EncryptionEncValues[] | undefined;
    readonly userinfoSigningAlgValuesSupported?: readonly SigningAlgorithmWithNone[] | undefined;

    [key: string]: unknown;

    static find(id: string): Promise<Client | undefined>;
    static validate(metadata: ClientMetadata): Promise<void>;
}

export type {
    AccessToken,
    AuthorizationCode,
    BackchannelAuthenticationRequest,
    Claims,
    Client,
    ClientCredentials,
    DeviceCode,
    Grant,
    IdToken,
    InitialAccessToken,
    Interaction,
    OIDCContext,
    PreAuthorizedCode,
    PushedAuthorizationRequest,
    RefreshToken,
    RegistrationAccessToken,
    ReplayDetection,
    Session,
};

// @generate oidcContext

export type KoaContextWithOIDC = Koa.ParameterizedContext<
    Koa.DefaultState,
    Koa.DefaultContext & {
        oidc: OIDCContext;
    }
>;

export interface TokenEndpointGrantParameters extends UnknownObject {
    grant_type: string;
    scope?: string | undefined;
    resource?: string | string[] | undefined;
    authorization_details?: string | undefined;
}

/** Context passed to a handler registered with `Provider.registerGrantType()`. */
export type TokenEndpointGrantContext<Params extends object = UnknownObject> = KoaContextWithOIDC & {
    oidc: OIDCContext & {
        readonly provider: Provider;
        readonly client: Client;
        readonly params: TokenEndpointGrantParameters & Params;
        readonly resourceServers: { [identifier: string]: ResourceServerInstance };
    };
};

/* eslint-disable @typescript-eslint/no-invalid-void-type */
// @generate contracts
/* eslint-enable @typescript-eslint/no-invalid-void-type */

export interface HttpOptions {
    signal?: AbortSignal | undefined;
    agent?: http.Agent | https.Agent | undefined;
    dnsLookup?: typeof dns.lookup | undefined;
    "user-agent"?: string | undefined;
}
export type AsymmetricSigningAlgorithm =
    | "PS256"
    | "PS384"
    | "PS512"
    | "Ed25519"
    | "ES256"
    | "ES384"
    | "ES512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ML-DSA-44"
    | "ML-DSA-65"
    | "ML-DSA-87"
    | "EdDSA";
export type SymmetricSigningAlgorithm = "HS256" | "HS384" | "HS512";
export type SigningAlgorithm = AsymmetricSigningAlgorithm | SymmetricSigningAlgorithm;
export type SigningAlgorithmWithNone = AsymmetricSigningAlgorithm | SymmetricSigningAlgorithm;
export type EncryptionAlgValues =
    | "RSA-OAEP"
    | "RSA-OAEP-256"
    | "RSA-OAEP-384"
    | "RSA-OAEP-512"
    | "ECDH-ES"
    | "ECDH-ES+A128KW"
    | "ECDH-ES+A192KW"
    | "ECDH-ES+A256KW"
    | "A128KW"
    | "A192KW"
    | "A256KW"
    | "A128GCMKW"
    | "A192GCMKW"
    | "A256GCMKW"
    | "dir";
export type EncryptionEncValues =
    | "A128CBC-HS256"
    | "A128GCM"
    | "A192CBC-HS384"
    | "A192GCM"
    | "A256CBC-HS512"
    | "A256GCM";

export interface InteractionResults {
    login?:
        | {
            remember?: boolean | undefined;
            accountId: string;
            ts?: number | undefined;
            amr?: string[] | undefined;
            acr?: string | undefined;
            [key: string]: unknown;
        }
        | undefined;

    consent?:
        | {
            grantId?: string | undefined;
            [key: string]: unknown;
        }
        | undefined;

    [key: string]: unknown;
}

export default class Provider extends Koa {
    constructor(issuer: string, configuration?: Configuration);

    readonly issuer: string;

    /**
     * @deprecated
     */
    readonly app: Koa;

    static get ctx(): KoaContextWithOIDC | undefined;

    // @generate providerMembers

    readonly Grant: typeof Grant;
    readonly Client: typeof Client;
    readonly AccessToken: typeof AccessToken;
    readonly InitialAccessToken: typeof InitialAccessToken;
    readonly RefreshToken: typeof RefreshToken;
    readonly AuthorizationCode: typeof AuthorizationCode;
    readonly RegistrationAccessToken: typeof RegistrationAccessToken;
    readonly PushedAuthorizationRequest: typeof PushedAuthorizationRequest;
    readonly ClientCredentials: typeof ClientCredentials;
    readonly DeviceCode: typeof DeviceCode;
    readonly BackchannelAuthenticationRequest: typeof BackchannelAuthenticationRequest;
    readonly PreAuthorizedCode: typeof PreAuthorizedCode;
    readonly BaseToken: typeof BaseToken;
    readonly IdToken: typeof IdToken;
    readonly Claims: typeof Claims;
    readonly ReplayDetection: typeof ReplayDetection;
    readonly ResourceServer: {
        new(identifier: string, data: ResourceServer): ResourceServerInstance;
    };
    readonly OIDCContext: typeof OIDCContext;
    readonly Session: typeof Session;
    readonly Interaction: typeof Interaction;
}

// @generate relatedContracts

export { Provider };
