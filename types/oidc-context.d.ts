/**
 * Source template for extension-facing declarations owned by oidc-provider.
 *
 * This file is not published. Its declarations are rendered into the matching
 * generated region in @types/oidc-provider.
 */

declare class OIDCContext {
    constructor(ctx: Koa.Context);
    readonly route: string;

    readonly cookies: {
        get(name: string, opts?: { signed?: boolean | undefined }): string | undefined;
        set(name: string, value: string | null, opts?: CookiesSetOptions): undefined;
    };

    readonly entities: {
        readonly AccessToken?: AccessToken | undefined;
        readonly Account?: Account | undefined;
        readonly AuthorizationCode?: AuthorizationCode | undefined;
        readonly Client?: Client | undefined;
        readonly Grant?: Grant | undefined;
        readonly ClientCredentials?: ClientCredentials | undefined;
        readonly DeviceCode?: DeviceCode | undefined;
        readonly IdTokenHint?: { header: UnknownObject; payload: UnknownObject } | undefined;
        readonly InitialAccessToken?: InitialAccessToken | undefined;
        readonly Interaction?: Interaction | undefined;
        readonly PushedAuthorizationRequest?: PushedAuthorizationRequest | undefined;
        readonly PreAuthorizedCode?: PreAuthorizedCode | undefined;
        readonly BackchannelAuthenticationRequest?: BackchannelAuthenticationRequest | undefined;
        readonly RefreshToken?: RefreshToken | undefined;
        readonly RegistrationAccessToken?: RegistrationAccessToken | undefined;
        readonly RotatedRefreshToken?: RefreshToken | undefined;
        readonly RotatedRegistrationAccessToken?: RegistrationAccessToken | undefined;
        readonly Session?: Session | undefined;
        readonly [key: string]: unknown;
    };
    readonly claims: ClaimsParameter;
    readonly issuer: string;
    readonly provider: Provider;
    readonly resourceServers?: { [key: string]: ResourceServerInstance } | undefined;
    readonly fapiProfile?: FapiProfile | undefined;
    readonly clientAttestation?:
        | {
            method: "attestation_pop_jwt" | "dpop_combined";
            signal: boolean;
            attestation: JWTVerificationResult;
            pop: JWTVerificationResult;
        }
        | undefined;

    entity(key: string, value: any): void;

    urlFor(name: string, options?: UnknownObject): string;
    isFapi(...profiles: FapiProfile[]): FapiProfile | undefined;
    promptPending(name: string): boolean;

    readonly requestParamClaims: Set<string>;
    readonly requestParamScopes: Set<string>;
    readonly requestParamOIDCScopes: Set<string>;
    readonly prompts: Set<string>;
    readonly responseMode?: string | undefined;
    readonly result?: InteractionResults | undefined;

    readonly redirectUriCheckPerformed?: boolean | undefined;
    readonly trusted?: string[] | undefined;
    readonly registrationAccessToken?: RegistrationAccessToken | undefined;
    readonly deviceCode?: DeviceCode | undefined;
    readonly authorizationCode?: AuthorizationCode | undefined;
    readonly refreshToken?: RefreshToken | undefined;
    readonly accessToken?: AccessToken | undefined;
    readonly account?: Account | undefined;
    readonly client?: Client | undefined;
    readonly grant?: Grant | undefined;
    readonly session?: Session | undefined;
    readonly acr: string;
    readonly amr: string[];
    readonly body?: UnknownObject | undefined;
    readonly params?: UnknownObject | undefined;

    getAccessToken(opts?: { acceptDPoP?: boolean | undefined; acceptQueryParam?: boolean | undefined }): string;

    clientJwtAuthExpectedAudience(): Set<string>;
}
