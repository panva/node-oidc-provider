/**
 * Source template for extension-facing declarations owned by oidc-provider.
 *
 * This file is not published. Its declarations are rendered into the matching
 * generated region in @types/oidc-provider.
 */

declare class Checks extends Array<interactionPolicy.Check> {
    get(reason: string): interactionPolicy.Check | undefined;
    remove(reason: string): void;
    clear(): void;
    add(check: interactionPolicy.Check, index?: number): void;
}

export namespace interactionPolicy {
    interface DefaultPolicy extends Array<Prompt> {
        get(name: string): Prompt | undefined;
        remove(name: string): void;
        clear(): void;
        add(prompt: Prompt, index?: number): void;
    }

    class Check {
        static readonly REQUEST_PROMPT: true;
        static readonly NO_NEED_TO_PROMPT: false;

        constructor(
            reason: string,
            description: string,
            error: string,
            check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>,
            details?: (ctx: KoaContextWithOIDC) => CanBePromise<UnknownObject | undefined>,
        );
        constructor(
            reason: string,
            description: string,
            check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>,
            details?: (ctx: KoaContextWithOIDC) => CanBePromise<UnknownObject | undefined>,
        );

        reason: string;
        description: string;
        error: string | undefined;
        details: (ctx: KoaContextWithOIDC) => CanBePromise<UnknownObject | undefined>;
        check: (ctx: KoaContextWithOIDC) => CanBePromise<boolean>;
    }

    class Prompt {
        constructor(info: { name: string; requestable?: boolean | undefined }, ...checks: Check[]);
        constructor(
            info: { name: string; requestable?: boolean | undefined },
            details: (ctx: KoaContextWithOIDC) => CanBePromise<UnknownObject | undefined>,
            ...checks: Check[]
        );

        name: string;
        requestable: boolean;
        details: (ctx: KoaContextWithOIDC) => CanBePromise<UnknownObject | undefined>;
        checks: Checks;
    }

    function base(): DefaultPolicy;
}

export namespace errors {
    interface OIDCProviderErrorOptions {
        cause?: unknown;
        detail?: string;
    }

    class OIDCProviderError extends Error {
        constructor(status: number, message: string, options?: OIDCProviderErrorOptions);
        cause?: unknown;
        error: string;
        error_description?: string | undefined;
        error_detail?: string | undefined;
        expose: boolean;
        statusCode: number;
        status: number;
        allow_redirect: boolean;
    }
    class ExpiredLoginHintToken extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidBindingMessage extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidAuthorizationDetails extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidCredentialRequest extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidNonce extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidUserCode extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class MissingUserCode extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class TransactionFailed extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnknownUserId extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class AccessDenied extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class AuthorizationPending extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class ConsentRequired extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class ExpiredToken extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InteractionRequired extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidClient extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidDpopProof extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidClientAuth extends OIDCProviderError {
        constructor(options?: string | OIDCProviderErrorOptions);
    }
    class InvalidClientMetadata extends OIDCProviderError {
        constructor(description: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidGrant extends OIDCProviderError {
        constructor(options?: string | OIDCProviderErrorOptions);
    }
    class InvalidRequest extends OIDCProviderError {
        constructor(description: string, code?: number, options?: string | OIDCProviderErrorOptions);
    }
    class SessionNotFound extends InvalidRequest {}
    class InvalidRequestObject extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidRequestUri extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidProof extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidScope extends OIDCProviderError {
        constructor(description: string, scope: string, options?: string | OIDCProviderErrorOptions);
    }
    class InsufficientScope extends OIDCProviderError {
        constructor(description: string, scope: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidSoftwareStatement extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidTarget extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnknownCredentialConfiguration extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnknownCredentialIdentifier extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidToken extends OIDCProviderError {
        constructor(options?: string | OIDCProviderErrorOptions);
    }
    class LoginRequired extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidRedirectUri extends OIDCProviderError {
        constructor(options?: OIDCProviderErrorOptions);
        constructor(description?: string, detail?: string);
    }
    class RegistrationNotSupported extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class RequestNotSupported extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class RequestUriNotSupported extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class SlowDown extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class TemporarilyUnavailable extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnapprovedSoftwareStatement extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnauthorizedClient extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnsupportedGrantType extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnsupportedResponseMode extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnsupportedResponseType extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class CustomOIDCProviderError extends OIDCProviderError {
        constructor(message: string, description?: string, options?: OIDCProviderErrorOptions);
    }
    class CredentialRequestDenied extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UseDpopNonce extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnsupportedTokenType extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UseAttestationChallenge extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UseFreshAttestation extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class InvalidClientAttestation extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
    class UnmetAuthenticationRequirements extends OIDCProviderError {
        constructor(description?: string, options?: string | OIDCProviderErrorOptions);
    }
}
