declare module 'oidc-provider' {
    import { Request, Response, Handler } from 'express';
    import Koa = require('koa');
    import Router = require('koa-router');
    import { IncomingMessage, ServerResponse } from 'http';
    import EventEmitter = require('events');
    import { JWK } from 'node-jose';

    type SubjectType = 'public' | 'parwise';

    interface IClient {
        applicationType?: 'web' | 'native';
        grant_types?: string[];
        id_token_signed_response_alg?: string;
        require_auth_time?: boolean;
        response_types?: string[];
        subject_type?: SubjectType;
        token_endpoint_auth_method?: string;
        request_uris?: string[];
        client_id?: string;
        client_secret?: string;
        redirect_uris: string[];
        introspection_endpoint_auth_method?: string;
    }

    interface IAdapter {
        upsert: (id: string, payload: string, expiresIn: number) => Promise<void>;
        find: (id: string) => Promise<void>;
        findByUserCode: (userCode: string) => Promise<void>;
        consume: (id: string) => Promise<void>;
        destroy: (id: string) => Promise<void>;
        connect?: (provider: Provider) => Promise<void>;
        key: (id: string) => string;
    }

    interface IKeystore {
        keys: object[];
    }

    interface ISession {
        _id: string;
        accountId: string | null;
        expiresAt: Date;
        save(time: number): Promise<void>;
        sidFor(client_id: string): boolean;
        login: {};
        interaction: {
            error?: 'login_required';
            error_description: string;
            reason: 'no_session' | 'consent_prompt' | 'client_not_authorized';
            reason_description: string;
        };
        params: {
            client_id: string;
            redirect_uri: string;
            response_mode: 'query';
            response_type: 'code';
            login_hint?: string;
            scope: 'openid';
            state: string;
        };
        returnTo: string;
        signed: null;
        uuid: string;
        id: string;
    }

    interface IConfigurationFeatures {
        devInteractions?: boolean;
        discovery?: boolean;
        requestUri?: boolean;
        oauthNativeApps?: boolean;
        pkce?: boolean;
        alwaysIssueRefresh?: boolean;
        backchannelLogout?: boolean;
        certificateBoundAccessTokens?: boolean;
        claimsParameter?: boolean;
        clientCredentials?: boolean;
        conformIdTokenClaims?: boolean;
        deviceFlow?: boolean;
        encryption?: boolean;
        frontchannelLogout?: boolean;
        introspection?: boolean;
        jwtIntrospection?: boolean;
        jwtResponseModes?: boolean;
        registration?: boolean;
        registrationManagement?: boolean;
        resourceIndicators?: boolean;
        request?: boolean;
        revocation?: boolean;
        sessionManagement?: boolean;
        webMessageResponseMode?: boolean;
    }

    interface ICookieOptions {
        secure?: boolean;
        signed?: boolean;
        httpOnly?: boolean;
        maxAge?: number;
    }

    type InteractionResult =
        | boolean
        | {
              error: string;
              error_description: string;
              reason: string;
              reason_description: string;
          };

    interface IRoutes {
        authorization?: string;
        certificates?: string;
        check_session?: string;
        device_authorization?: string;
        end_session?: string;
        introspection?: string;
        registration?: string;
        revocation?: string;
        token?: string;
        userinfo?: string;
        code_verification?: string;
    }

    interface IConfiguration {
        features?: IConfigurationFeatures;
        acrValues?: string[];
        audiences?: (
            ctx: Koa.Context,
            sub: string,
            token: string,
            use: 'id_token' | 'userinfo' | 'access_token' | 'client_credentials'
        ) => string[] | boolean;
        claims?: object;
        clientCacheDuration?: number;
        clockTolerance?: number;
        cookies?: {
            keys: string[];
            long?: ICookieOptions;
            names?: object;
            short?: ICookieOptions;
        };
        deviceFlowSuccess?: (ctx: Koa.Context) => void;
        discovery?: object;
        dynamicScopes?: string[];
        extraClientMetadata?: {
            properties?: string[];
            validator?: (key: string, value: string, metadata: object) => void;
        };
        extraParams?: string[];
        findById?: (
            ctx: Koa.Context,
            sub: string,
            token: string
        ) => Promise<{
            accountId: string;
            claims: (use: string, scope: string, claims: object, rejected: string[]) => Promise<object> | object;
        }>;
        formats?: {
            default?: string;
            AccessToken?: string | ((token: string) => string);
            AuthorizationCode?: string | ((token: string) => string);
            RefreshToken?: string | ((token: string) => string);
            DeviceCode?: string | ((token: string) => string);
            ClientCredentials?: string | ((token: string) => string);
            InitialAccessToken?: string | ((token: string) => string);
            RegistrationAccessToken?: string | ((token: string) => string);
        };
        frontchannelLogoutPendingSource?: (
            ctx: Koa.Context,
            frames: string[],
            postLogoutRedirectUri: string,
            timeout: number
        ) => void;
        interactionCheck?: (ctx: Koa.Context) => InteractionResult;
        interactionUrl?: (ctx: Koa.Context, interaction: InteractionResult) => void;
        introspectionEndpointAuthMethods?: string[];
        logoutSource?: (ctx: Koa.Context, form: string) => void;
        pairwiseIdentifier?: (accountId: string, client: object) => string;
        postLogoutRedirectUri?: (ctx: Koa.Context) => string;
        prompts?: string[];
        refreshTokenRotation?: 'rotateAndConsume' | 'none';
        renderError?: (ctx: Koa.Context, out: object, error: Error) => void;
        responseTypes?: string[];
        revocationEndpointAuthMethods?: string[];
        routes?: IRoutes;
        scopes?: string[];
        subjectTypes?: SubjectType;
        tokenEndpointAuthMethods?: string[];
        ttl?: {
            AccessToken?: number;
            AuthorizationCode?: number;
            ClientCredentials?: number;
            DeviceCode?: number;
            IdToken?: number;
            RefreshToken?: number;
        };
        uniqueness?: (ctx: Koa.Context, jti: string, expiresAt: number) => boolean;
        userCodeConfirmSource?: (ctx: Koa.Context, form: string, client: object, deviceInfo: object) => void;
        userCodeInputSource?: (ctx: Koa.Context, form: string, out: object, err: Error) => void;
        whitelistedJWA?: {
            authorizationEncryptionAlgValues?:
                | 'RSA-OAEP'
                | 'RSA1_5'
                | 'ECDH-ES'
                | 'ECDH-ES+A128KW'
                | 'ECDH-ES+A192KW'
                | 'ECDH-ES+A256KW'
                | 'A128KW'
                | 'A192KW'
                | 'A256KW'
                | 'A128GCMKW'
                | 'A192GCMKW'
                | 'A256GCMKW'
                | 'PBES2-HS256+A128KW'
                | 'PBES2-HS384+A192KW'
                | 'PBES2-HS512+A256KW';
            authorizationEncryptionEncValues?:
                | 'A128CBC-HS256'
                | 'A128GCM'
                | 'A192CBC-HS384'
                | 'A192GCM'
                | 'A256CBC-HS512'
                | 'A256GCM';
            authorizationSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            idTokenEncryptionAlgValues?:
                | 'RSA-OAEP'
                | 'RSA1_5'
                | 'ECDH-ES'
                | 'ECDH-ES+A128KW'
                | 'ECDH-ES+A192KW'
                | 'ECDH-ES+A256KW'
                | 'A128KW'
                | 'A192KW'
                | 'A256KW'
                | 'A128GCMKW'
                | 'A192GCMKW'
                | 'A256GCMKW'
                | 'PBES2-HS256+A128KW'
                | 'PBES2-HS384+A192KW'
                | 'PBES2-HS512+A256KW';
            idTokenEncryptionEncValues?:
                | 'A128CBC-HS256'
                | 'A128GCM'
                | 'A192CBC-HS384'
                | 'A192GCM'
                | 'A256CBC-HS512'
                | 'A256GCM';
            idTokenSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            introspectionEncryptionAlgValues?:
                | 'RSA-OAEP'
                | 'RSA1_5'
                | 'ECDH-ES'
                | 'ECDH-ES+A128KW'
                | 'ECDH-ES+A192KW'
                | 'ECDH-ES+A256KW'
                | 'A128KW'
                | 'A192KW'
                | 'A256KW'
                | 'A128GCMKW'
                | 'A192GCMKW'
                | 'A256GCMKW'
                | 'PBES2-HS256+A128KW'
                | 'PBES2-HS384+A192KW'
                | 'PBES2-HS512+A256KW';
            introspectionEncryptionEncValues?:
                | 'A128CBC-HS256'
                | 'A128GCM'
                | 'A192CBC-HS384'
                | 'A192GCM'
                | 'A256CBC-HS512'
                | 'A256GCM';
            introspectionEndpointAuthSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            introspectionSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            requestObjectEncryptionAlgValues?:
                | 'RSA-OAEP'
                | 'RSA1_5'
                | 'ECDH-ES'
                | 'ECDH-ES+A128KW'
                | 'ECDH-ES+A192KW'
                | 'ECDH-ES+A256KW'
                | 'A128KW'
                | 'A192KW'
                | 'A256KW'
                | 'A128GCMKW'
                | 'A192GCMKW'
                | 'A256GCMKW'
                | 'PBES2-HS256+A128KW'
                | 'PBES2-HS384+A192KW'
                | 'PBES2-HS512+A256KW';
            requestObjectEncryptionEncValues?:
                | 'A128CBC-HS256'
                | 'A128GCM'
                | 'A192CBC-HS384'
                | 'A192GCM'
                | 'A256CBC-HS512'
                | 'A256GCM';
            requestObjectSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            revocationEndpointAuthSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            tokenEndpointAuthSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            userinfoEncryptionAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
            userinfoEncryptionEncValues?:
                | 'A128CBC-HS256'
                | 'A128GCM'
                | 'A192CBC-HS384'
                | 'A192GCM'
                | 'A256CBC-HS512'
                | 'A256GCM';
            userinfoSigningAlgValues?:
                | 'HS256'
                | 'HS384'
                | 'HS512'
                | 'RS256'
                | 'RS384'
                | 'RS512'
                | 'PS256'
                | 'PS384'
                | 'PS512'
                | 'ES256'
                | 'ES384'
                | 'ES512';
        };
    }

    class Provider extends EventEmitter {
        app: Koa;

        domain: {};

        proxy: boolean;

        constructor(url: string, config?: IConfiguration);

        initialize(config: { adapter?: (new(name: string) => IAdapter); clients?: IClient[]; keystore?: unknown }): Promise<this>;

        interactionDetails(ctx: IncomingMessage): Promise<ISession>;

        setProviderSession(req: IncomingMessage, res: ServerResponse, {}): Promise<ISession>;

        interactionFinished(req: IncomingMessage, res: ServerResponse, {}): Promise<void>;

        callback: Handler;
        listen(port: string | number): void;

        Client: IClient;

        session: ISession;

        params: {
            response_type: 'none';
        };
        result: boolean;
    }

    export const createKeyStore: JWK.createKeyStore;
    export const asKeyStore: JWK.asKeyStore;
    export const asKey: JWK.asKey;

    export default Provider;
}
