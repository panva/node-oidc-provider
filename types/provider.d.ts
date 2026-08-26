/**
 * Source template for Provider methods whose contracts are owned by oidc-provider.
 *
 * This wrapper is not published. The type generator extracts its class body and
 * replaces the event-listener placeholder block with overloads rendered
 * from ./events.js.
 */
export declare class ProviderExtensibilityContract {
    urlFor(name: string, options?: UnknownObject): string;
    pathFor(name: string, options?: UnknownObject & { mountPath?: string | undefined }): string;
    cookieName(type: string): string;

    registerResponseMode(
        name: string,
        handler: (
            ctx: KoaContextWithOIDC,
            redirectUri: string,
            payload: UnknownObject,
        ) => CanBePromise<void>,
    ): void;

    backchannelResult(
        request: BackchannelAuthenticationRequest | string,
        result: Grant | errors.OIDCProviderError | string,
        opts?: {
            acr?: string | undefined;
            amr?: string[] | undefined;
            authTime?: number | undefined;
            sessionUid?: string | undefined;
            expiresWithSession?: boolean | undefined;
            sid?: string | undefined;
            rar?: AuthorizationDetail[] | undefined;
        },
    ): Promise<void>;

    interactionResult(
        req: http.IncomingMessage | http2.Http2ServerRequest,
        res: http.ServerResponse | http2.Http2ServerResponse,
        result: InteractionResults,
        options?: { mergeWithLastSubmission?: boolean | undefined },
    ): Promise<string>;

    interactionFinished(
        req: http.IncomingMessage | http2.Http2ServerRequest,
        res: http.ServerResponse | http2.Http2ServerResponse,
        result: InteractionResults,
        options?: { mergeWithLastSubmission?: boolean | undefined },
    ): Promise<void>;

    interactionDetails(
        req: http.IncomingMessage | http2.Http2ServerRequest,
        res: http.ServerResponse | http2.Http2ServerResponse,
    ): Promise<Interaction>;

    registerGrantType<Params extends object = UnknownObject>(
        name: string,
        handler: (ctx: TokenEndpointGrantContext<Params>) => CanBePromise<void>,
        params?: string | readonly string[] | ReadonlySet<string>,
        duplicates?: string | readonly string[] | ReadonlySet<string>,
    ): void;

    // @generate-event-listener-overloads begin
    addListener(event: never, listener: never): this;
    on(event: never, listener: never): this;
    once(event: never, listener: never): this;
    prependListener(event: never, listener: never): this;
    prependOnceListener(event: never, listener: never): this;
    // @generate-event-listener-overloads end
}
