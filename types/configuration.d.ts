/**
 * Canonical provider-owned configuration and extension contracts.
 *
 * This source-only declaration template is rendered into the declarations published by
 * DefinitelyTyped. Configuration prose and defaults remain canonical in
 * `lib/helpers/defaults.js`.
 *
 * Types referenced but not declared here are stable supporting declarations retained by
 * DefinitelyTyped.
 */

export type FindAccount = (
    ctx: KoaContextWithOIDC,
    sub: string,
    token?:
        | AuthorizationCode
        | AccessToken
        | RefreshToken
        | DeviceCode
        | BackchannelAuthenticationRequest
        | PreAuthorizedCode,
) => CanBePromise<Account | undefined>;
export type TokenFormat = "opaque" | "jwt";
export type FapiProfile = "1.0 Final" | "2.0";

/**
 * A synchronous TTL policy callback. The returned number of seconds must be a
 * positive safe integer.
 */
export type TTLFunction<T, WithClient extends boolean = true> = WithClient extends true
    ? (ctx: KoaContextWithOIDC, token: T, client: Client) => number
    : (ctx: KoaContextWithOIDC, token: T) => number;

export interface AuthorizationDetail extends UnknownObject {
    type: string;
}

export interface JWTVerificationResult {
    protectedHeader: UnknownObject;
    payload: UnknownObject;
    key: crypto.KeyObject | crypto.webcrypto.CryptoKey;
}

export interface KeyAttestation {
    jwt: string;
    attestedKeys: readonly JWK[];
    payload: UnknownObject;
}

export interface OpenID4VCIProofType {
    proof_signing_alg_values_supported?: readonly string[] | undefined;
    key_attestations_required?:
        | {
            key_storage?: readonly string[] | undefined;
            user_authentication?: readonly string[] | undefined;
        }
        | undefined;
    [key: string]: unknown;
}

export interface OpenID4VCICredentialConfiguration {
    format: string;
    scope?: string | undefined;
    cryptographic_binding_methods_supported?: readonly "jwk"[] | undefined;
    proof_types_supported?:
        | {
            jwt?: OpenID4VCIProofType | undefined;
            attestation?: OpenID4VCIProofType | undefined;
        }
        | undefined;
    [key: string]: unknown;
}

export interface OpenID4VCIMetadata extends UnknownObject {
    batch_credential_issuance?:
        | {
            batch_size: number;
            [key: string]: unknown;
        }
        | undefined;
}

export type OpenID4VCIProofs =
    | {
        jwt: readonly string[];
        key_attestation?: KeyAttestation | undefined;
        attestation?: never;
    }
    | {
        attestation: KeyAttestation;
        jwt?: never;
        key_attestation?: never;
    };

export interface OpenID4VCICredentialContext {
    credentialConfigurationId: string;
    credentialConfiguration: OpenID4VCICredentialConfiguration;
    credentialIdentifier?: string | undefined;
    client: Client;
    account: Account;
    grant: Grant;
    accessToken: AccessToken;
}

export interface OpenID4VCIIssueCredentialContext extends OpenID4VCICredentialContext {
    body: UnknownObject;
    proofs?: OpenID4VCIProofs | undefined;
}

export interface OpenID4VCICredentialResponse extends UnknownObject {
    credentials: readonly unknown[];
    notification_id?: string | undefined;
}

export interface ResourceServer {
    scope: string;
    audience?: string | undefined;
    /** A positive safe integer number of seconds. */
    accessTokenTTL?: number | undefined;
    accessTokenFormat?: TokenFormat | undefined;
    jwt?:
        | {
            sign?:
                | false
                | {
                    alg?: AsymmetricSigningAlgorithm | undefined;
                    kid?: string | undefined;
                }
                | {
                    alg: SymmetricSigningAlgorithm;
                    key: crypto.KeyObject | crypto.webcrypto.CryptoKey | Buffer;
                    kid?: string | undefined;
                }
                | undefined;
            encrypt?:
                | false
                | {
                    alg: EncryptionAlgValues;
                    enc: EncryptionEncValues;
                    key: crypto.KeyObject | crypto.webcrypto.CryptoKey | Buffer;
                    kid?: string | undefined;
                }
                | undefined;
        }
        | undefined;
}

export interface ResourceServerInstance extends ResourceServer {
    readonly scopes: Set<string>;
    identifier(): string;
}

export type TLSClientAuthProperty =
    | "tls_client_auth_subject_dn"
    | "tls_client_auth_san_dns"
    | "tls_client_auth_san_uri"
    | "tls_client_auth_san_ip"
    | "tls_client_auth_san_email";

export interface AccountClaims {
    sub: string;

    [key: string]: unknown;
}

export interface Account {
    accountId: string;
    claims: (
        use: string,
        scope: string,
        claims: { [key: string]: null | ClaimsParameterMember },
        rejected: string[],
    ) => CanBePromise<AccountClaims>;
    [key: string]: unknown;
}

export type RotateRegistrationAccessTokenFunction = Exclude<
    (
        | boolean
        | ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>)
    ),
    boolean
>;
export type IssueRegistrationAccessTokenFunction = Exclude<
    (
        | boolean
        | ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>)
    ),
    boolean
>;

export interface ErrorOut {
    error: string;
    error_description?: string | undefined;
    scope?: string | undefined;
    state?: string | undefined;
}

export interface AdapterPayload extends AllClientMetadata {
    accountId?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    aud?: string | string[] | undefined;
    authorizations?:
        | {
            [clientId: string]: ClientAuthorizationState;
        }
        | undefined;
    authTime?: number | undefined;
    claims?: ClaimsParameter | undefined;
    cid?: string | undefined;
    clientId?: string | undefined;
    codeChallenge?: string | undefined;
    codeChallengeMethod?: string | undefined;
    consumed?: any;
    deviceCode?: string | undefined;
    deviceInfo?: UnknownObject | undefined;
    error?: string | undefined;
    errorDescription?: string | undefined;
    exp?: number | undefined;
    expiresWithSession?: boolean | undefined;
    extra?: UnknownObject | undefined;
    format?: string | undefined;
    grantId?: string | undefined;
    gty?: string | undefined;
    iat?: number | undefined;
    iiat?: number | undefined;
    inFlight?: boolean | undefined;
    jti?: string | undefined;
    kind?: string | undefined;
    lastSubmission?: InteractionResults | undefined;
    loginTs?: number | undefined;
    nonce?: string | undefined;
    parJti?: string | undefined;
    params?: UnknownObject | undefined;
    policies?: string[] | undefined;
    prompt?: PromptDetail | undefined;
    redirectUri?: string | undefined;
    request?: string | undefined;
    rar?: AuthorizationDetail[] | undefined;
    resource?: string | string[] | undefined;
    result?: InteractionResults | undefined;
    returnTo?: string | undefined;
    rotations?: number | undefined;
    scope?: string | undefined;
    session?:
        | {
            accountId?: string | undefined;
            acr?: string | undefined;
            amr?: string[] | undefined;
            cookie?: string | undefined;
            uid?: string | undefined;
        }
        | undefined;
    sessionUid?: string | undefined;
    sid?: string | undefined;
    trusted?: string[] | undefined;
    attestationJkt?: string | undefined;
    dpopJkt?: string | undefined;
    iss?: string | undefined;
    state?: UnknownObject | undefined;
    transient?: boolean | undefined;
    uid?: string | undefined;
    userCode?: string | undefined;
    txCode?: string | undefined;
    jkt?: string | undefined;
    "x5t#S256"?: string | undefined;
}

export interface Adapter {
    upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    find(id: string): Promise<AdapterPayload | undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    findByUserCode(userCode: string): Promise<AdapterPayload | undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    findByUid(uid: string): Promise<AdapterPayload | undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    consume(id: string): Promise<undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    destroy(id: string): Promise<undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
    revokeByGrantId(grantId: string): Promise<undefined | void>; // eslint-disable-line @typescript-eslint/no-invalid-void-type
}

export type AdapterFactory = (name: string) => Adapter;

export interface AdapterConstructor {
    new(name: string): Adapter;
}

export interface CookiesSetOptions {
    path?: string | undefined;
    domain?: string | undefined;
    secure?: boolean | undefined;
    httpOnly?: boolean | undefined;
    partitioned?: boolean | undefined;
    priority?: "low" | "medium" | "high" | undefined;
    sameSite?: boolean | "strict" | "lax" | "none" | undefined;
    signed?: boolean | undefined;
    overwrite?: boolean | undefined;
}

export interface JWTStructured {
    header?: UnknownObject | undefined;
    payload: UnknownObject;
}

export type JsonObject = { [Key in string]?: JsonValue };
export type JsonArray = JsonValue[];
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

type RichAuthorizationRequestTypeBase = ({
    [type: string]: {
        validate: (
            ctx: KoaContextWithOIDC,
            detail: AuthorizationDetail,
            client: Client,
        ) => CanBePromise<void>;
    };
})[string];

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface RichAuthorizationRequestType extends RichAuthorizationRequestTypeBase {}

export type AuthorizationDetailsForGrantSource = (
    ctx: KoaContextWithOIDC,
    source: AuthorizationCode | DeviceCode,
) => CanBePromise<readonly AuthorizationDetail[] | undefined>;

export type AuthorizationDetailsForAccessToken = (
    ctx: KoaContextWithOIDC,
    token: AccessToken | ClientCredentials,
    source:
        | AuthorizationCode
        | BackchannelAuthenticationRequest
        | DeviceCode
        | PreAuthorizedCode
        | RefreshToken
        | undefined,
    grantType: string,
) => CanBePromise<readonly AuthorizationDetail[] | undefined>;

export type AuthorizationDetailsForIntrospection = (
    ctx: KoaContextWithOIDC,
    token: AccessToken | ClientCredentials | RefreshToken,
) => CanBePromise<readonly AuthorizationDetail[] | undefined>;

export interface RichAuthorizationRequestsConfigurationBase {
    enabled?: boolean | undefined;
    // @configuration-path features.richAuthorizationRequests.types
    // @configuration-dynamic features.richAuthorizationRequests.types
    types?: Readonly<Record<string, RichAuthorizationRequestType>> | undefined;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForGrantSource
    authorizationDetailsForGrantSource?: AuthorizationDetailsForGrantSource | undefined;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForAccessToken
    authorizationDetailsForAccessToken?: AuthorizationDetailsForAccessToken | undefined;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForIntrospection
    authorizationDetailsForIntrospection?: AuthorizationDetailsForIntrospection | undefined;
}

export interface RichAuthorizationRequestsDisabledConfiguration extends RichAuthorizationRequestsConfigurationBase {
    enabled?: false | undefined;
}

export interface RichAuthorizationRequestsInactiveConfiguration extends RichAuthorizationRequestsConfigurationBase {
    enabled: boolean;
    // @configuration-docs features.richAuthorizationRequests.types
    types?: Readonly<Record<string, never>> | undefined;
}

export interface RichAuthorizationRequestsActiveConfiguration extends RichAuthorizationRequestsConfigurationBase {
    enabled: boolean;
    // @configuration-path features.richAuthorizationRequests.types
    types: Readonly<Record<string, RichAuthorizationRequestType>>;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForGrantSource
    authorizationDetailsForGrantSource: AuthorizationDetailsForGrantSource;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForAccessToken
    authorizationDetailsForAccessToken: AuthorizationDetailsForAccessToken;
}

export type RichAuthorizationRequestsConfiguration =
    | RichAuthorizationRequestsDisabledConfiguration
    | RichAuthorizationRequestsInactiveConfiguration
    | RichAuthorizationRequestsActiveConfiguration;

export interface FapiDisabledConfiguration {
    enabled?: false | undefined;
    // @configuration-path features.fapi.profile
    profile?:
        | (
            | FapiProfile
            | ((
                ctx: KoaContextWithOIDC,
                client: Client,
            ) => FapiProfile | undefined)
        )
        | undefined;
}

export interface FapiEnabledConfiguration {
    enabled: boolean;
    // @configuration-path features.fapi.profile
    profile:
        | FapiProfile
        | ((
            ctx: KoaContextWithOIDC,
            client: Client,
        ) => FapiProfile | undefined);
}

export type FapiConfiguration = FapiDisabledConfiguration | FapiEnabledConfiguration;

export type CIBATriggerAuthenticationDevice = (
    ctx: KoaContextWithOIDC,
    request: BackchannelAuthenticationRequest,
    account: Account,
    client: Client,
) => CanBePromise<void>;

export type CIBAValidateRequestContext = (
    ctx: KoaContextWithOIDC,
    requestContext?: string,
) => CanBePromise<void>;

export type CIBAVerifyUserCode = (
    ctx: KoaContextWithOIDC,
    account: Account,
    userCode?: string,
) => CanBePromise<void>;

export interface CIBAConfigurationBase {
    enabled?: boolean | undefined;
    // @configuration-path features.ciba.deliveryModes
    deliveryModes?: readonly CIBADeliveryMode[] | ReadonlySet<CIBADeliveryMode> | undefined;
    // @configuration-path features.ciba.triggerAuthenticationDevice
    triggerAuthenticationDevice?: CIBATriggerAuthenticationDevice | undefined;
    // @configuration-path features.ciba.validateBindingMessage
    validateBindingMessage?:
        | ((
            ctx: KoaContextWithOIDC,
            bindingMessage?: string,
        ) => CanBePromise<void>)
        | undefined;
    // @configuration-path features.ciba.validateRequestContext
    validateRequestContext?: CIBAValidateRequestContext | undefined;
    // @configuration-path features.ciba.processLoginHintToken
    processLoginHintToken?:
        | ((
            ctx: KoaContextWithOIDC,
            loginHintToken?: string,
        ) => CanBePromise<string | undefined>)
        | undefined;
    // @configuration-path features.ciba.processLoginHint
    processLoginHint?:
        | ((
            ctx: KoaContextWithOIDC,
            loginHint?: string,
        ) => CanBePromise<string | undefined>)
        | undefined;
    // @configuration-path features.ciba.verifyUserCode
    verifyUserCode?: CIBAVerifyUserCode | undefined;
}

export interface CIBADisabledConfiguration extends CIBAConfigurationBase {
    enabled?: false | undefined;
}

export interface CIBAEnabledConfiguration extends CIBAConfigurationBase {
    enabled: boolean;
    // @configuration-path features.ciba.triggerAuthenticationDevice
    triggerAuthenticationDevice: CIBATriggerAuthenticationDevice;
    // @configuration-path features.ciba.validateRequestContext
    validateRequestContext: CIBAValidateRequestContext;
    // @configuration-path features.ciba.verifyUserCode
    verifyUserCode: CIBAVerifyUserCode;
}

export type CIBAConfiguration = CIBADisabledConfiguration | CIBAEnabledConfiguration;

export type MTLSGetCertificate = (
    ctx: KoaContextWithOIDC,
) => crypto.X509Certificate | string | undefined;
export type MTLSCertificateAuthorized = (ctx: KoaContextWithOIDC) => boolean;
export type MTLSCertificateSubjectMatches = (
    ctx: KoaContextWithOIDC,
    property: TLSClientAuthProperty,
    expected: string,
) => boolean;

export interface MTLSConfigurationBase {
    enabled?: boolean | undefined;
    // @configuration-path features.mTLS.certificateBoundAccessTokens
    certificateBoundAccessTokens?: boolean | undefined;
    // @configuration-path features.mTLS.selfSignedTlsClientAuth
    selfSignedTlsClientAuth?: boolean | undefined;
    // @configuration-path features.mTLS.tlsClientAuth
    tlsClientAuth?: boolean | undefined;
    // @configuration-path features.mTLS.getCertificate
    getCertificate?: MTLSGetCertificate | undefined;
    // @configuration-path features.mTLS.certificateAuthorized
    certificateAuthorized?: MTLSCertificateAuthorized | undefined;
    // @configuration-path features.mTLS.certificateSubjectMatches
    certificateSubjectMatches?: MTLSCertificateSubjectMatches | undefined;
}

export interface MTLSDisabledConfiguration extends MTLSConfigurationBase {
    enabled?: false | undefined;
}

export interface MTLSEnabledWithoutCertificateConfiguration extends MTLSConfigurationBase {
    enabled: boolean;
    // @configuration-path features.mTLS.certificateBoundAccessTokens
    certificateBoundAccessTokens?: false | undefined;
    // @configuration-path features.mTLS.selfSignedTlsClientAuth
    selfSignedTlsClientAuth?: false | undefined;
    // @configuration-path features.mTLS.tlsClientAuth
    tlsClientAuth?: false | undefined;
}

export type MTLSEnabledCertificateConfiguration =
    & MTLSConfigurationBase
    & {
        enabled: boolean;
        // @configuration-path features.mTLS.tlsClientAuth
        tlsClientAuth?: false | undefined;
        // @configuration-path features.mTLS.getCertificate
        getCertificate: MTLSGetCertificate;
    }
    & (
        | {
            // @configuration-path features.mTLS.certificateBoundAccessTokens
            certificateBoundAccessTokens: true;
        }
        | {
            // @configuration-path features.mTLS.selfSignedTlsClientAuth
            selfSignedTlsClientAuth: true;
        }
    );

export interface MTLSEnabledClientAuthenticationConfiguration extends MTLSConfigurationBase {
    enabled: boolean;
    // @configuration-path features.mTLS.tlsClientAuth
    tlsClientAuth: true;
    // @configuration-path features.mTLS.getCertificate
    getCertificate: MTLSGetCertificate;
    // @configuration-path features.mTLS.certificateAuthorized
    certificateAuthorized: MTLSCertificateAuthorized;
    // @configuration-path features.mTLS.certificateSubjectMatches
    certificateSubjectMatches: MTLSCertificateSubjectMatches;
}

export type MTLSEnabledDynamicCertificateFlagsConfiguration =
    & MTLSConfigurationBase
    & {
        enabled: boolean;
        // @configuration-path features.mTLS.getCertificate
        getCertificate: MTLSGetCertificate;
        // @configuration-path features.mTLS.tlsClientAuth
        tlsClientAuth?: false | undefined;
    }
    & (
        | {
            // @configuration-path features.mTLS.certificateBoundAccessTokens
            certificateBoundAccessTokens: boolean;
        }
        | {
            // @configuration-path features.mTLS.selfSignedTlsClientAuth
            selfSignedTlsClientAuth: boolean;
        }
    );

export interface MTLSEnabledDynamicTlsClientAuthConfiguration extends MTLSConfigurationBase {
    enabled: boolean;
    // @configuration-path features.mTLS.tlsClientAuth
    tlsClientAuth: boolean;
    // @configuration-path features.mTLS.getCertificate
    getCertificate: MTLSGetCertificate;
    // @configuration-path features.mTLS.certificateAuthorized
    certificateAuthorized: MTLSCertificateAuthorized;
    // @configuration-path features.mTLS.certificateSubjectMatches
    certificateSubjectMatches: MTLSCertificateSubjectMatches;
}

export type MTLSConfiguration =
    | MTLSDisabledConfiguration
    | MTLSEnabledWithoutCertificateConfiguration
    | MTLSEnabledCertificateConfiguration
    | MTLSEnabledClientAuthenticationConfiguration
    | MTLSEnabledDynamicCertificateFlagsConfiguration
    | MTLSEnabledDynamicTlsClientAuthConfiguration;

export type AttestationSignaturePublicKey = (
    ctx: KoaContextWithOIDC,
    header: UnknownObject,
    payload: UnknownObject,
    client: Client,
) => CanBePromise<crypto.KeyObject | crypto.webcrypto.CryptoKey | JWK>;

export interface AttestClientAuthConfigurationBase {
    enabled?: boolean | undefined;
    ack?: string | undefined;
    // @configuration-path features.attestClientAuth.additionalSecuritySignal
    additionalSecuritySignal?: false | "optional" | "required" | undefined;
    // @configuration-path features.attestClientAuth.challengeSecret
    challengeSecret?: Buffer | undefined;
    // @configuration-path features.attestClientAuth.getAttestationSignaturePublicKey
    getAttestationSignaturePublicKey?: AttestationSignaturePublicKey | undefined;
    // @configuration-path features.attestClientAuth.assertAttestationJwtAndPop
    assertAttestationJwtAndPop?:
        | ((
            ctx: KoaContextWithOIDC,
            attestation: JWTVerificationResult,
            pop: JWTVerificationResult,
            client: Client,
        ) => CanBePromise<void>)
        | undefined;
}

export interface AttestClientAuthDisabledConfiguration extends AttestClientAuthConfigurationBase {
    enabled?: false | undefined;
}

export interface AttestClientAuthEnabledConfiguration extends AttestClientAuthConfigurationBase {
    enabled: boolean;
    // @configuration-path features.attestClientAuth.challengeSecret
    challengeSecret: Buffer;
    // @configuration-path features.attestClientAuth.getAttestationSignaturePublicKey
    getAttestationSignaturePublicKey: AttestationSignaturePublicKey;
}

export type AttestClientAuthConfiguration =
    | AttestClientAuthDisabledConfiguration
    | AttestClientAuthEnabledConfiguration;

export type OpenID4VCIIssueCredential = (
    ctx: KoaContextWithOIDC,
    details: OpenID4VCIIssueCredentialContext,
) => CanBePromise<OpenID4VCICredentialResponse>;

export type OpenID4VCIKeyAttestationSignaturePublicKey = (
    ctx: KoaContextWithOIDC,
    issuer: string,
    header: UnknownObject,
    client: Client,
) => CanBePromise<crypto.KeyObject | crypto.webcrypto.CryptoKey | JWK>;

export interface OpenID4VCIConfigurationBase {
    enabled?: boolean | undefined;
    ack?: string | undefined;
    // @configuration-path features.openid4vci.nonceSecret
    nonceSecret?: Buffer | undefined;
    // @configuration-path features.openid4vci.preAuthorizedCodeGrant
    preAuthorizedCodeGrant?: boolean | undefined;
    // @configuration-path features.openid4vci.metadata
    // @configuration-dynamic features.openid4vci.metadata
    metadata?: OpenID4VCIMetadata | undefined;
    // @configuration-path features.openid4vci.credentialConfigurationsSupported
    // @configuration-dynamic features.openid4vci.credentialConfigurationsSupported
    credentialConfigurationsSupported?:
        | Readonly<Record<string, OpenID4VCICredentialConfiguration>>
        | undefined;
    // @configuration-path features.openid4vci.credentialEndpointExpectedAudience
    credentialEndpointExpectedAudience?:
        | ((ctx: KoaContextWithOIDC) => CanBePromise<string>)
        | undefined;
    // @configuration-path features.openid4vci.credentialConfigurationPolicy
    credentialConfigurationPolicy?:
        | ((
            ctx: KoaContextWithOIDC,
            details: OpenID4VCICredentialContext,
        ) => CanBePromise<boolean>)
        | undefined;
    // @configuration-path features.openid4vci.issueCredential
    issueCredential?: OpenID4VCIIssueCredential | undefined;
    // @configuration-path features.openid4vci.getKeyAttestationSignaturePublicKey
    getKeyAttestationSignaturePublicKey?: OpenID4VCIKeyAttestationSignaturePublicKey | undefined;
}

export interface OpenID4VCIDisabledConfiguration extends OpenID4VCIConfigurationBase {
    enabled?: false | undefined;
}

export interface OpenID4VCIEnabledConfiguration extends OpenID4VCIConfigurationBase {
    enabled: boolean;
    // @configuration-path features.openid4vci.nonceSecret
    nonceSecret: Buffer;
    // @configuration-path features.openid4vci.credentialConfigurationsSupported
    credentialConfigurationsSupported: Readonly<Record<string, OpenID4VCICredentialConfiguration>>;
    // @configuration-path features.openid4vci.issueCredential
    issueCredential: OpenID4VCIIssueCredential;
}

export type OpenID4VCIConfiguration = OpenID4VCIDisabledConfiguration | OpenID4VCIEnabledConfiguration;

interface IntrospectionFeatureBase {
    enabled?: boolean | undefined;
    // @configuration-path features.introspection.allowedPolicy
    allowedPolicy?:
        | ((
            ctx: KoaContextWithOIDC,
            client: Client,
            token: AccessToken | ClientCredentials | RefreshToken,
        ) => CanBePromise<boolean>)
        | undefined;
}

interface IntrospectionDisabledFeature extends IntrospectionFeatureBase {
    enabled?: false | undefined;
}

interface IntrospectionPossiblyEnabledFeature extends IntrospectionFeatureBase {
    enabled: boolean;
}

type RichAuthorizationRequestsActiveWithIntrospection = RichAuthorizationRequestsActiveConfiguration & {
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForIntrospection
    authorizationDetailsForIntrospection: AuthorizationDetailsForIntrospection;
};

type RichAuthorizationRequestsEnabledByOpenID4VCI = RichAuthorizationRequestsConfigurationBase & {
    enabled: boolean;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForGrantSource
    authorizationDetailsForGrantSource: AuthorizationDetailsForGrantSource;
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForAccessToken
    authorizationDetailsForAccessToken: AuthorizationDetailsForAccessToken;
};

type RichAuthorizationRequestsEnabledByOpenID4VCIWithIntrospection = RichAuthorizationRequestsEnabledByOpenID4VCI & {
    // @configuration-path features.richAuthorizationRequests.authorizationDetailsForIntrospection
    authorizationDetailsForIntrospection: AuthorizationDetailsForIntrospection;
};

type ConditionalRichAuthorizationRequestFeatures =
    | {
        // @configuration-path features.openid4vci
        openid4vci: OpenID4VCIEnabledConfiguration;
        // @configuration-path features.introspection
        introspection: IntrospectionPossiblyEnabledFeature;
        // @configuration-path features.richAuthorizationRequests
        richAuthorizationRequests?:
            | RichAuthorizationRequestsDisabledConfiguration
            | RichAuthorizationRequestsEnabledByOpenID4VCIWithIntrospection
            | undefined;
    }
    | {
        // @configuration-docs features.openid4vci
        openid4vci: OpenID4VCIEnabledConfiguration;
        // @configuration-docs features.introspection
        introspection?: IntrospectionDisabledFeature | undefined;
        // @configuration-docs features.richAuthorizationRequests
        richAuthorizationRequests?:
            | RichAuthorizationRequestsDisabledConfiguration
            | RichAuthorizationRequestsEnabledByOpenID4VCI
            | undefined;
    }
    | {
        // @configuration-docs features.openid4vci
        openid4vci?: OpenID4VCIDisabledConfiguration | undefined;
        // @configuration-docs features.introspection
        introspection: IntrospectionPossiblyEnabledFeature;
        // @configuration-docs features.richAuthorizationRequests
        richAuthorizationRequests?:
            | RichAuthorizationRequestsDisabledConfiguration
            | RichAuthorizationRequestsInactiveConfiguration
            | RichAuthorizationRequestsActiveWithIntrospection
            | undefined;
    }
    | {
        // @configuration-docs features.openid4vci
        openid4vci?: OpenID4VCIDisabledConfiguration | undefined;
        // @configuration-docs features.introspection
        introspection?: IntrospectionDisabledFeature | undefined;
        // @configuration-docs features.richAuthorizationRequests
        richAuthorizationRequests?: RichAuthorizationRequestsConfiguration | undefined;
    };

export interface Configuration {
    // @configuration-path acrValues
    acrValues?: readonly string[] | ReadonlySet<string> | undefined;

    // @configuration-path adapter
    adapter?: AdapterConstructor | AdapterFactory | undefined;

    // @configuration-path claims
    // @configuration-dynamic claims
    claims?:
        | {
            [key: string]: null | readonly string[] | Readonly<Record<string, null>>;
        }
        | undefined;

    // @configuration-path clientBasedCORS
    clientBasedCORS?: ((ctx: KoaContextWithOIDC, origin: string, client: Client) => boolean) | undefined;

    // @configuration-path clients
    // @configuration-dynamic clients
    clients?: readonly ClientMetadata[] | undefined;

    formats?:
        | {
            // @configuration-path formats.bitsOfOpaqueRandomness
            bitsOfOpaqueRandomness?: (number | ((ctx: KoaContextWithOIDC, model: BaseModel) => number)) | undefined;
            // @configuration-path formats.customizers
            customizers?:
                | ({
                    jwt?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            token: AccessToken | ClientCredentials,
                            parts: JWTStructured,
                        ) => CanBePromise<void>)
                        | undefined;
                })
                | undefined;
        }
        | undefined;

    // @configuration-path clientDefaults
    // @configuration-dynamic clientDefaults
    clientDefaults?: AllClientMetadata | undefined;

    // @configuration-path clockTolerance
    clockTolerance?: number | undefined;

    // @configuration-path conformIdTokenClaims
    conformIdTokenClaims?: boolean | undefined;

    // @configuration-path cookies
    cookies?:
        | {
            // @configuration-path cookies.names
            names?:
                | {
                    session?: string | undefined;
                    interaction?: string | undefined;
                    resume?: string | undefined;
                }
                | undefined;
            // @configuration-path cookies.long
            long?: CookiesSetOptions | undefined;
            // @configuration-path cookies.short
            short?: CookiesSetOptions | undefined;
            // @configuration-path cookies.keys
            keys?: ReadonlyArray<string | Buffer> | undefined | KeyGrip;
        }
        | undefined;

    // @configuration-path discovery
    // @configuration-dynamic discovery
    discovery?: UnknownObject | undefined;

    // @configuration-path enableHttpPostMethods
    enableHttpPostMethods?: boolean | undefined;

    // @configuration-path extraParams
    // @configuration-dynamic extraParams
    extraParams?:
        | (readonly string[] | ReadonlySet<string> | {
            [name: string]:
                | null
                | ((
                    ctx: KoaContextWithOIDC,
                    value: string | undefined,
                    client: Client,
                ) => CanBePromise<void>);
        })
        | undefined;

    // @configuration-path assertJwtClientAuthClaimsAndHeader
    assertJwtClientAuthClaimsAndHeader?:
        | ((
            ctx: KoaContextWithOIDC,
            claims: Record<string, JsonValue>,
            header: Record<string, JsonValue>,
            client: Client,
        ) => CanBePromise<void>)
        | undefined;

    // @configuration-path features
    features?:
        | {
            // @configuration-path features.devInteractions
            devInteractions?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.claimsParameter
            claimsParameter?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.claimsParameter.assertClaimsParameter
                    assertClaimsParameter?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            claims: ClaimsParameter,
                            client: Client,
                        ) => CanBePromise<void>)
                        | undefined;
                }
                | undefined;

            // @configuration-path features.clientIdMetadataDocument
            clientIdMetadataDocument?:
                | {
                    enabled?: boolean | undefined;
                    ack?: string | undefined;
                    // @configuration-path features.clientIdMetadataDocument.allowFetch
                    allowFetch?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            clientId: string,
                        ) => CanBePromise<boolean>)
                        | undefined;
                    // @configuration-path features.clientIdMetadataDocument.allowClient
                    allowClient?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            client: Client,
                        ) => CanBePromise<boolean>)
                        | undefined;
                    // @configuration-path features.clientIdMetadataDocument.cacheDuration
                    cacheDuration?:
                        | {
                            min?: number | undefined;
                            max?: number | undefined;
                        }
                        | undefined;
                }
                | undefined;

            // @configuration-path features.clientCredentials
            clientCredentials?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.revocation
            revocation?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.revocation.allowedPolicy
                    allowedPolicy?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            client: Client,
                            token: AccessToken | ClientCredentials | RefreshToken,
                        ) => CanBePromise<boolean>)
                        | undefined;
                }
                | undefined;

            // @configuration-path features.userinfo
            userinfo?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.jwtUserinfo
            jwtUserinfo?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.encryption
            encryption?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.registration
            registration?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.registration.initialAccessToken
                    initialAccessToken?: boolean | string | undefined;
                    // @configuration-path features.registration.policies
                    // @configuration-dynamic features.registration.policies
                    policies?:
                        | ({
                            [name: string]: (
                                ctx: KoaContextWithOIDC,
                                metadata: ClientMetadata,
                            ) => CanBePromise<undefined | void>;
                        })
                        | undefined;
                    // @configuration-path features.registration.idFactory
                    idFactory?: ((ctx: KoaContextWithOIDC) => string) | undefined;
                    // @configuration-path features.registration.secretFactory
                    secretFactory?: ((ctx: KoaContextWithOIDC) => CanBePromise<string>) | undefined;
                    // @configuration-path features.registration.issueRegistrationAccessToken
                    issueRegistrationAccessToken?:
                        | (
                            | boolean
                            | ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>)
                        )
                        | undefined;
                }
                | undefined;

            // @configuration-path features.registrationManagement
            registrationManagement?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.registrationManagement.rotateRegistrationAccessToken
                    rotateRegistrationAccessToken?:
                        | (
                            | boolean
                            | ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>)
                        )
                        | undefined;
                }
                | undefined;

            // @configuration-path features.deviceFlow
            deviceFlow?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.deviceFlow.charset
                    charset?: "base-20" | "digits" | undefined;
                    // @configuration-path features.deviceFlow.mask
                    mask?: string | undefined;
                    // @configuration-path features.deviceFlow.deviceInfo
                    deviceInfo?: ((ctx: KoaContextWithOIDC) => UnknownObject) | undefined;
                    // @configuration-path features.deviceFlow.userCodeInputSource
                    userCodeInputSource?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            form: string,
                            out?: ErrorOut,
                            err?: errors.OIDCProviderError | Error,
                        ) => CanBePromise<undefined | void>)
                        | undefined;
                    // @configuration-path features.deviceFlow.userCodeConfirmSource
                    userCodeConfirmSource?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            form: string,
                            client: Client,
                            deviceInfo: UnknownObject,
                            userCode: string,
                        ) => CanBePromise<undefined | void>)
                        | undefined;
                    // @configuration-path features.deviceFlow.successSource
                    successSource?: ((ctx: KoaContextWithOIDC) => CanBePromise<undefined | void>) | undefined;
                }
                | undefined;

            // @configuration-path features.requestObjects
            requestObjects?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.requestObjects.requireSignedRequestObject
                    requireSignedRequestObject?: boolean | undefined;
                    // @configuration-path features.requestObjects.assertJwtClaimsAndHeader
                    assertJwtClaimsAndHeader?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            claims: Record<string, JsonValue>,
                            header: Record<string, JsonValue>,
                            client: Client,
                        ) => CanBePromise<void>)
                        | undefined;
                }
                | undefined;

            // @configuration-path features.dPoP
            dPoP?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.dPoP.nonceSecret
                    nonceSecret?: Buffer | undefined;
                    // @configuration-path features.dPoP.requireNonce
                    requireNonce?: ((ctx: KoaContextWithOIDC) => boolean) | undefined;
                    // @configuration-path features.dPoP.allowReplay
                    allowReplay?: boolean;
                }
                | undefined;

            // @configuration-path features.backchannelLogout
            backchannelLogout?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.fapi
            fapi?: FapiConfiguration | undefined;

            // @configuration-path features.ciba
            ciba?: CIBAConfiguration | undefined;

            // @configuration-path features.webMessageResponseMode
            webMessageResponseMode?:
                | {
                    enabled?: boolean | undefined;
                    ack?: string | undefined;
                }
                | undefined;

            // @configuration-path features.jwtIntrospection
            jwtIntrospection?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.jwtResponseModes
            jwtResponseModes?:
                | {
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.pushedAuthorizationRequests
            pushedAuthorizationRequests?:
                | {
                    // @configuration-path features.pushedAuthorizationRequests.requirePushedAuthorizationRequests
                    requirePushedAuthorizationRequests?: boolean | undefined;
                    // @configuration-path features.pushedAuthorizationRequests.allowUnregisteredRedirectUris
                    allowUnregisteredRedirectUris?: boolean | undefined;
                    enabled?: boolean | undefined;
                }
                | undefined;

            // @configuration-path features.rpInitiatedLogout
            rpInitiatedLogout?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.rpInitiatedLogout.postLogoutSuccessSource
                    postLogoutSuccessSource?:
                        | ((ctx: KoaContextWithOIDC) => CanBePromise<undefined | void>)
                        | undefined;
                    // @configuration-path features.rpInitiatedLogout.logoutSource
                    logoutSource?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            form: string,
                        ) => CanBePromise<undefined | void>)
                        | undefined;
                }
                | undefined;

            // @configuration-path features.mTLS
            mTLS?: MTLSConfiguration | undefined;

            // @configuration-path features.resourceIndicators
            resourceIndicators?:
                | {
                    enabled?: boolean | undefined;
                    // @configuration-path features.resourceIndicators.getResourceServerInfo
                    getResourceServerInfo?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            resourceIndicator: string,
                            client: Client,
                        ) => CanBePromise<ResourceServer>)
                        | undefined;
                    // @configuration-path features.resourceIndicators.defaultResource
                    defaultResource?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            client: Client,
                            oneOf?: readonly string[] | undefined,
                        ) => CanBePromise<string | readonly string[] | undefined>)
                        | undefined;
                    // @configuration-path features.resourceIndicators.useGrantedResource
                    useGrantedResource?:
                        | ((
                            ctx: KoaContextWithOIDC,
                            model:
                                | AuthorizationCode
                                | RefreshToken
                                | DeviceCode
                                | BackchannelAuthenticationRequest
                                | PreAuthorizedCode,
                        ) => CanBePromise<boolean>)
                        | undefined;
                }
                | undefined;

            // @configuration-path features.rpMetadataChoices
            rpMetadataChoices?: {
                enabled?: boolean | undefined;
            } | undefined;

            // @configuration-path features.externalSigningSupport
            externalSigningSupport?: {
                enabled?: boolean | undefined;
                ack?: string | undefined;
            } | undefined;

            // @configuration-path features.attestClientAuth
            attestClientAuth?: AttestClientAuthConfiguration | undefined;
        } & ConditionalRichAuthorizationRequestFeatures
        | undefined;

    // @configuration-path extraTokenClaims
    extraTokenClaims?:
        | ((
            ctx: KoaContextWithOIDC,
            token: AccessToken | ClientCredentials,
        ) => CanBePromise<UnknownObject | undefined>)
        | undefined;

    // @configuration-path fetch
    fetch?:
        | ((
            input: string | URL | Request,
            init?: RequestInit,
        ) => Promise<Response>)
        | undefined;

    // @configuration-path fetchResponseBodyLimits
    // @configuration-dynamic fetchResponseBodyLimits
    fetchResponseBodyLimits?:
        | {
            "client_id metadata document"?: number | undefined;
            jwks_uri?: number | undefined;
            sector_identifier_uri?: number | undefined;
            [purpose: string]: number | undefined;
        }
        | undefined;

    // @configuration-path expiresWithSession
    expiresWithSession?:
        | ((
            ctx: KoaContextWithOIDC,
            source: AccessToken | AuthorizationCode | DeviceCode,
        ) => CanBePromise<boolean>)
        | undefined;

    // @configuration-path issueRefreshToken
    issueRefreshToken?:
        | ((
            ctx: KoaContextWithOIDC,
            client: Client,
            source: AuthorizationCode | DeviceCode | BackchannelAuthenticationRequest | PreAuthorizedCode,
        ) => CanBePromise<boolean>)
        | undefined;

    // @configuration-path jwks
    jwks?: JWKS | undefined;

    // @configuration-path responseTypes
    responseTypes?: readonly ResponseType[] | undefined;

    // @configuration-path revokeGrantPolicy
    revokeGrantPolicy?: ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>) | undefined;

    // @configuration-path pkce
    pkce?:
        | {
            // @configuration-path pkce.required
            required?: ((ctx: KoaContextWithOIDC, client: Client) => boolean) | undefined;
        }
        | undefined;

    // @configuration-path routes
    routes?:
        | {
            authorization?: string | undefined;
            code_verification?: string | undefined;
            device_authorization?: string | undefined;
            challenge?: string | undefined;
            credential?: string | undefined;
            end_session?: string | undefined;
            introspection?: string | undefined;
            jwks?: string | undefined;
            registration?: string | undefined;
            revocation?: string | undefined;
            token?: string | undefined;
            userinfo?: string | undefined;
            backchannel_authentication?: string | undefined;
            pushed_authorization_request?: string | undefined;
        }
        | undefined;

    // @configuration-path scopes
    scopes?: readonly string[] | ReadonlySet<string> | undefined;

    // @configuration-path subjectTypes
    subjectTypes?: readonly SubjectTypes[] | ReadonlySet<SubjectTypes> | undefined;

    // @configuration-path pairwiseIdentifier
    pairwiseIdentifier?:
        | ((
            ctx: KoaContextWithOIDC,
            accountId: string,
            client: Client,
        ) => CanBePromise<string>)
        | undefined;

    // @configuration-path clientAuthMethods
    clientAuthMethods?: readonly ClientAuthMethod[] | ReadonlySet<ClientAuthMethod> | undefined;

    // @configuration-path ttl
    // @configuration-dynamic ttl
    ttl?:
        | ({
            AccessToken?:
                | number
                | ((ctx: KoaContextWithOIDC, token: AccessToken, client: Client) => number)
                | undefined;
            AuthorizationCode?:
                | number
                | ((ctx: KoaContextWithOIDC, code: AuthorizationCode, client: Client) => number)
                | undefined;
            BackchannelAuthenticationRequest?:
                | number
                | ((ctx: KoaContextWithOIDC, request: BackchannelAuthenticationRequest, client: Client) => number)
                | undefined;
            ClientCredentials?:
                | number
                | ((ctx: KoaContextWithOIDC, token: ClientCredentials, client: Client) => number)
                | undefined;
            DeviceCode?: number | ((ctx: KoaContextWithOIDC, code: DeviceCode, client: Client) => number) | undefined;
            Grant?: number | ((ctx: KoaContextWithOIDC, grant: Grant) => number) | undefined;
            IdToken?: number | ((ctx: KoaContextWithOIDC, token: IdToken, client: Client) => number) | undefined;
            Interaction?: number | ((ctx: KoaContextWithOIDC, interaction: Interaction) => number) | undefined;
            PreAuthorizedCode?: number | ((ctx: KoaContextWithOIDC, code: PreAuthorizedCode) => number) | undefined;
            RefreshToken?:
                | number
                | ((ctx: KoaContextWithOIDC, token: RefreshToken, client: Client) => number)
                | undefined;
            Session?: number | ((ctx: KoaContextWithOIDC, session: Session) => number) | undefined;
            [key: string]: unknown;
        })
        | undefined;

    // @configuration-path loadExistingGrant
    loadExistingGrant?: ((ctx: KoaContextWithOIDC) => CanBePromise<Grant | undefined>) | undefined;

    // @configuration-path extraClientMetadata
    extraClientMetadata?:
        | {
            // @configuration-path extraClientMetadata.properties
            properties?: readonly string[] | undefined;

            // @configuration-path extraClientMetadata.validator
            validator?:
                | ((
                    ctx: KoaContextWithOIDC | undefined,
                    key: string,
                    value: unknown,
                    metadata: ClientMetadata,
                ) => void | undefined)
                | undefined;
        }
        | undefined;

    // @configuration-path rotateRefreshToken
    rotateRefreshToken?: ((ctx: KoaContextWithOIDC) => CanBePromise<boolean>) | boolean | undefined;

    // @configuration-path renderError
    renderError?:
        | ((
            ctx: KoaContextWithOIDC,
            out: ErrorOut,
            error: errors.OIDCProviderError | Error,
        ) => CanBePromise<void | undefined>)
        | undefined;

    // @configuration-path allowOmittingSingleRegisteredRedirectUri
    allowOmittingSingleRegisteredRedirectUri?: boolean | undefined;

    // @configuration-path acceptQueryParamAccessTokens
    acceptQueryParamAccessTokens?: boolean | undefined;

    // @configuration-path interactions
    interactions?:
        | {
            // @configuration-path interactions.policy
            policy?: (readonly interactionPolicy.Prompt[]) | undefined;
            // @configuration-path interactions.url
            url?:
                | ((
                    ctx: KoaContextWithOIDC,
                    interaction: Interaction,
                ) => CanBePromise<string>)
                | undefined;
        }
        | undefined;

    // @configuration-path findAccount
    findAccount?: FindAccount | undefined;

    // @configuration-path sectorIdentifierUriValidate
    sectorIdentifierUriValidate?: ((client: Client) => boolean) | undefined;

    // @configuration-path enabledJWA
    enabledJWA?:
        | {
            // @configuration-path enabledJWA.authorizationEncryptionAlgValues
            authorizationEncryptionAlgValues?: readonly EncryptionAlgValues[] | undefined;
            // @configuration-path enabledJWA.authorizationEncryptionEncValues
            authorizationEncryptionEncValues?: readonly EncryptionEncValues[] | undefined;
            // @configuration-path enabledJWA.authorizationSigningAlgValues
            authorizationSigningAlgValues?: readonly SigningAlgorithm[] | undefined;
            // @configuration-path enabledJWA.dPoPSigningAlgValues
            dPoPSigningAlgValues?: readonly AsymmetricSigningAlgorithm[] | undefined;
            // @configuration-path enabledJWA.attestSigningAlgValues
            attestSigningAlgValues?: readonly AsymmetricSigningAlgorithm[] | undefined;
            // @configuration-path enabledJWA.idTokenEncryptionAlgValues
            idTokenEncryptionAlgValues?: readonly EncryptionAlgValues[] | undefined;
            // @configuration-path enabledJWA.idTokenEncryptionEncValues
            idTokenEncryptionEncValues?: readonly EncryptionEncValues[] | undefined;
            // @configuration-path enabledJWA.idTokenSigningAlgValues
            idTokenSigningAlgValues?: readonly SigningAlgorithmWithNone[] | undefined;
            // @configuration-path enabledJWA.introspectionEncryptionAlgValues
            introspectionEncryptionAlgValues?: readonly EncryptionAlgValues[] | undefined;
            // @configuration-path enabledJWA.introspectionEncryptionEncValues
            introspectionEncryptionEncValues?: readonly EncryptionEncValues[] | undefined;
            // @configuration-path enabledJWA.introspectionSigningAlgValues
            introspectionSigningAlgValues?: readonly SigningAlgorithmWithNone[] | undefined;
            // @configuration-path enabledJWA.requestObjectEncryptionAlgValues
            requestObjectEncryptionAlgValues?: readonly EncryptionAlgValues[] | undefined;
            // @configuration-path enabledJWA.requestObjectEncryptionEncValues
            requestObjectEncryptionEncValues?: readonly EncryptionEncValues[] | undefined;
            // @configuration-path enabledJWA.requestObjectSigningAlgValues
            requestObjectSigningAlgValues?: readonly SigningAlgorithmWithNone[] | undefined;
            // @configuration-path enabledJWA.clientAuthSigningAlgValues
            clientAuthSigningAlgValues?: readonly SigningAlgorithm[] | undefined;
            // @configuration-path enabledJWA.userinfoEncryptionAlgValues
            userinfoEncryptionAlgValues?: readonly EncryptionAlgValues[] | undefined;
            // @configuration-path enabledJWA.userinfoEncryptionEncValues
            userinfoEncryptionEncValues?: readonly EncryptionEncValues[] | undefined;
            // @configuration-path enabledJWA.userinfoSigningAlgValues
            userinfoSigningAlgValues?: readonly SigningAlgorithmWithNone[] | undefined;
        }
        | undefined;
}

export class ExternalSigningKey {
    get alg(): string | undefined;
    get crv(): string | undefined;
    get e(): string | undefined;
    get key_ops(): string[] | undefined;
    get kid(): string | undefined;
    get kty(): string;
    get n(): string | undefined;
    get pub(): string | undefined;
    get use(): "sig";
    get x(): string | undefined;
    get x5c(): string[] | undefined;
    get y(): string | undefined;

    keyObject(): Promise<crypto.KeyObject> | crypto.KeyObject;

    sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}
