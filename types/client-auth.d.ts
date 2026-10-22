/**
 * Source template for extension-facing declarations owned by oidc-provider.
 *
 * This file is not published. Its declarations are rendered into the matching
 * generated region in @types/oidc-provider.
 */

export type ClientAuthMethod =
    | "client_secret_basic"
    | "client_secret_post"
    | "client_secret_jwt"
    | "private_key_jwt"
    | "tls_client_auth"
    | "self_signed_tls_client_auth"
    | "attest_jwt_client_auth"
    | "attest_jwt_client_auth_dpop"
    | "none";
