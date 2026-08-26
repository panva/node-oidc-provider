/**
 * @typedef {[name: string, type: string, documentationName?: string]} EventArgument
 * @typedef {{
 *   name: string,
 *   arguments: EventArgument[],
 *   description: string,
 *   mapped: boolean,
 * }} ProviderEvent
 */

/**
 * @param {string} name
 * @param {EventArgument[]} args
 * @param {string} description
 * @param {boolean} [mapped]
 * @returns {ProviderEvent}
 */
function event(name, args, description, mapped = false) {
  return { name, arguments: args, description, mapped };
}

/**
 * Events represented by ProviderAdditionalEventMap in the current declaration.
 * Keeping this distinction preserves the existing generic overload behavior.
 *
 * @param {string} name
 * @param {EventArgument[]} args
 * @param {string} description
 * @returns {ProviderEvent}
 */
function additional(name, args, description) {
  return event(name, args, description, true);
}

/** @type {ProviderEvent[]} */
export default [
  event(
    'access_token.destroyed',
    [['accessToken', 'AccessToken', 'token']],
    'whenever an access token is destroyed',
  ),
  event(
    'access_token.saved',
    [['accessToken', 'AccessToken', 'token']],
    'whenever an opaque access token is saved',
  ),
  event(
    'access_token.issued',
    [['accessToken', 'AccessToken', 'token']],
    'whenever a structured access token is issued',
  ),
  event(
    'authorization_code.consumed',
    [['authorizationCode', 'AuthorizationCode', 'code']],
    'whenever an authorization code is consumed',
  ),
  event(
    'authorization_code.destroyed',
    [['authorizationCode', 'AuthorizationCode', 'code']],
    'whenever an authorization code is destroyed',
  ),
  event(
    'authorization_code.saved',
    [['authorizationCode', 'AuthorizationCode', 'code']],
    'whenever an authorization code is saved',
  ),
  event(
    'authorization.accepted',
    [['ctx', 'KoaContextWithOIDC']],
    'with every syntactically correct authorization request pending resolving',
  ),
  event(
    'authorization.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `authorization_endpoint`',
  ),
  event(
    'authorization.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['response?', 'UnknownObject'],
    ],
    'with every successfully completed authorization request; `response` is provided when a response object has been assembled',
  ),
  event(
    'backchannel.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'Error', 'error'],
      ['client', 'Client'],
      ['accountId', 'string'],
      ['sid', 'string'],
    ],
    'whenever an error is encountered for a client during backchannel-logout',
  ),
  event(
    'backchannel.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['client', 'Client'],
      ['accountId', 'string'],
      ['sid', 'string'],
    ],
    'whenever a client is successfully notified about logout through backchannel-logout features',
  ),
  additional(
    'backchannel_authentication.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `backchannel_authentication_endpoint`',
  ),
  event(
    'backchannel_authentication_request.consumed',
    [['request', 'BackchannelAuthenticationRequest']],
    'whenever a backchannel authentication request is consumed',
  ),
  event(
    'backchannel_authentication_request.destroyed',
    [['request', 'BackchannelAuthenticationRequest']],
    'whenever a backchannel authentication request is destroyed',
  ),
  event(
    'backchannel_authentication_request.saved',
    [['request', 'BackchannelAuthenticationRequest']],
    'whenever a backchannel authentication request is saved',
  ),
  additional(
    'challenge.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `challenge_endpoint`',
  ),
  event(
    'jwks.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `jwks_uri`',
  ),
  event(
    'client_credentials.destroyed',
    [['clientCredentials', 'ClientCredentials', 'token']],
    'whenever client credentials token is destroyed',
  ),
  event(
    'client_credentials.saved',
    [['clientCredentials', 'ClientCredentials', 'token']],
    'whenever an opaque client credentials token is saved',
  ),
  event(
    'client_credentials.issued',
    [['clientCredentials', 'ClientCredentials', 'token']],
    'whenever a structured client credentials token is issued',
  ),
  additional(
    'code_verification.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `code_verification` endpoint',
  ),
  additional(
    'credential.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `credential_endpoint`',
  ),
  additional(
    'device_authorization.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `device_authorization_endpoint`',
  ),
  additional(
    'device_authorization.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['body', 'UnknownObject'],
    ],
    'with every successful device authorization request',
  ),
  event(
    'device_code.consumed',
    [['deviceCode', 'DeviceCode', 'code']],
    'whenever a device code is consumed',
  ),
  event(
    'device_code.destroyed',
    [['deviceCode', 'DeviceCode', 'code']],
    'whenever a device code is destroyed',
  ),
  event(
    'device_code.saved',
    [['deviceCode', 'DeviceCode', 'code']],
    'whenever a device code is saved',
  ),
  additional(
    'device_resume.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered when resuming a device authorization grant interaction',
  ),
  event(
    'discovery.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `/.well-known/openid-configuration` endpoint',
  ),
  event(
    'end_session.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `end_session` endpoint',
  ),
  event(
    'end_session.success',
    [['ctx', 'KoaContextWithOIDC']],
    'with every success end session request',
  ),
  additional(
    'end_session_confirm.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `end_session` confirmation endpoint',
  ),
  additional(
    'end_session_success.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `end_session` success endpoint',
  ),
  event('grant.destroyed', [['grant', 'Grant']], 'whenever a grant is destroyed'),
  event(
    'grant.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `token_endpoint`',
  ),
  event(
    'grant.revoked',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['grantId', 'string'],
    ],
    'whenever tokens resulting from a single grant are about to be revoked. `grantId` is a random string. Use this to cascade the token revocation in cases where your adapter cannot provide this functionality',
  ),
  event('grant.saved', [['grant', 'Grant']], 'whenever a grant is saved'),
  event(
    'grant.success',
    [['ctx', 'KoaContextWithOIDC']],
    'with every successful grant request. Useful i.e. for collecting metrics or triggering any action you need to execute after succeeded grant',
  ),
  additional(
    'initial_access_token.destroyed',
    [['token', 'InitialAccessToken']],
    'whenever inital access token is destroyed',
  ),
  additional(
    'initial_access_token.saved',
    [['token', 'InitialAccessToken']],
    'whenever inital access token is saved',
  ),
  event(
    'interaction.destroyed',
    [['interaction', 'Interaction']],
    'whenever interaction session is destroyed',
  ),
  event(
    'interaction.ended',
    [['ctx', 'KoaContextWithOIDC']],
    'whenever interaction has been resolved and the authorization request continues being processed',
  ),
  event(
    'interaction.saved',
    [['interaction', 'Interaction']],
    'whenever interaction session is saved',
  ),
  event(
    'interaction.started',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['interaction', 'PromptDetail', 'prompt'],
    ],
    'whenever interaction is being requested from the end-user',
  ),
  event(
    'introspection.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `introspection_endpoint`',
  ),
  event(
    'replay_detection.destroyed',
    [['replayDetection', 'ReplayDetection', 'token']],
    'whenever a replay detection object is destroyed',
  ),
  event(
    'replay_detection.saved',
    [['replayDetection', 'ReplayDetection', 'token']],
    'whenever a replay detection object is saved',
  ),
  additional(
    'openid_credential_issuer.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `/.well-known/openid-credential-issuer` endpoint',
  ),
  additional(
    'pre_authorized_code.consumed',
    [['code', 'PreAuthorizedCode']],
    'whenever a pre-authorized code is consumed',
  ),
  additional(
    'pre_authorized_code.destroyed',
    [['code', 'PreAuthorizedCode']],
    'whenever a pre-authorized code is destroyed',
  ),
  additional(
    'pre_authorized_code.saved',
    [['code', 'PreAuthorizedCode']],
    'whenever a pre-authorized code is saved',
  ),
  event(
    'pushed_authorization_request.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered in the POST `pushed_authorization_request` endpoint',
  ),
  event(
    'pushed_authorization_request.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['client', 'Client'],
    ],
    'with every successful request object endpoint response',
  ),
  event(
    'pushed_authorization_request.destroyed',
    [['pushedAuthorizationRequest', 'PushedAuthorizationRequest', 'token']],
    'whenever a pushed authorization request object is destroyed',
  ),
  event(
    'pushed_authorization_request.saved',
    [['pushedAuthorizationRequest', 'PushedAuthorizationRequest', 'token']],
    'whenever a pushed authorization request object is saved',
  ),
  event(
    'refresh_token.consumed',
    [['refreshToken', 'RefreshToken', 'token']],
    'whenever a refresh token is consumed',
  ),
  event(
    'refresh_token.destroyed',
    [['refreshToken', 'RefreshToken', 'token']],
    'whenever a refresh token is destroyed',
  ),
  event(
    'refresh_token.saved',
    [['refreshToken', 'RefreshToken', 'token']],
    'whenever a refresh token is saved',
  ),
  event(
    'registration_access_token.destroyed',
    [['registrationAccessToken', 'RegistrationAccessToken', 'token']],
    'whenever registration access token is destroyed',
  ),
  event(
    'registration_access_token.saved',
    [['registrationAccessToken', 'RegistrationAccessToken', 'token']],
    'whenever registration access token is saved',
  ),
  event(
    'registration_create.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered in the POST `registration_endpoint`',
  ),
  event(
    'registration_create.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['client', 'Client'],
    ],
    'with every successful client registration request',
  ),
  event(
    'registration_delete.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered in the DELETE `registration_endpoint`',
  ),
  event(
    'registration_delete.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['client', 'Client'],
    ],
    'with every successful delete client registration request',
  ),
  event(
    'registration_read.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered in the GET `registration_endpoint`',
  ),
  event(
    'registration_update.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered in the PUT `registration_endpoint`',
  ),
  event(
    'registration_update.success',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['client', 'Client'],
    ],
    'with every successful update client registration request',
  ),
  event(
    'revocation.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `revocation_endpoint`',
  ),
  event(
    'server_error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'Error', 'error'],
    ],
    'whenever an exception is thrown or promise rejected from either the Provider or your provided adapters. If it comes from the library you should probably report it',
  ),
  event('session.destroyed', [['session', 'Session']], 'whenever session is destroyed'),
  event('session.saved', [['session', 'Session']], 'whenever session is saved'),
  event(
    'userinfo.error',
    [
      ['ctx', 'KoaContextWithOIDC'],
      ['err', 'errors.OIDCProviderError', 'error'],
    ],
    'whenever a handled error is encountered at the `userinfo_endpoint`',
  ),
];
