/* eslint-disable global-require */

const { struct, notEmpty } = require('./struct');
const defaults = require('../lib/helpers/defaults');
const { reduce } = require('lodash');

const authMethodValues = defaults.tokenEndpointAuthMethods;
const authMethods = notEmpty([struct.enum(authMethodValues)]);

const extraClientMetadata = require('./structs/extra_client_metadata');
const cookies = require('./structs/cookies');
const discovery = require('./structs/discovery');
const ttl = require('./structs/ttl');
const unsupported = require('./structs/unsupported');
const features = require('./structs/features');
const claims = require('./structs/claims');
const routes = require('./structs/routes');

module.exports = struct.intersection([
  struct({
    identifier: 'string & issuerIdentifier',
    claims,
    cookies,
    discovery,
    features,
    routes,
    ttl,
    tokenEndpointAuthMethods: authMethods,
    introspectionEndpointAuthMethods: authMethods,
    revocationEndpointAuthMethods: authMethods,
    extraClientMetadata,
    unsupported,
    acrValues: ['string'],
    clientCacheDuration: 'integer & positive | zero | infinity',
    clockTolerance: 'integer & positive | zero',
    prompts: ['string'],
    scopes: notEmpty(['string']),
    subjectTypes: notEmpty([struct.enum(['public', 'pairwise'])]),
    responseTypes: ['string & responseType'],
    extraParams: ['string'],
    pairwiseSalt: 'string',
    postLogoutRedirectUri: 'function',
    logoutSource: 'function',
    frontchannelLogoutPendingSource: 'function',
    uniqueness: 'function',
    renderError: 'function',
    interactionUrl: 'function',
    interactionCheck: 'function',
    audiences: 'function',
    findById: 'function',
    refreshTokenRotation: struct.enum(['rotateAndConsume', 'none']),
  }, reduce({
    acrValues: defaults.acrValues,
    refreshTokenRotation: defaults.refreshTokenRotation,
    clientCacheDuration: defaults.clientCacheDuration,
    pairwiseSalt: defaults.pairwiseSalt,
    clockTolerance: defaults.clockTolerance,
    tokenEndpointAuthMethods: defaults.tokenEndpointAuthMethods,
    introspectionEndpointAuthMethods: defaults.introspectionEndpointAuthMethods,
    revocationEndpointAuthMethods: defaults.revocationEndpointAuthMethods,
    extraParams: defaults.extraParams,
    scopes: defaults.scopes,
    subjectTypes: defaults.subjectTypes,
    prompts: defaults.prompts,
    responseTypes: defaults.responseTypes,
    logoutSource: defaults.logoutSource,
    frontchannelLogoutPendingSource: defaults.frontchannelLogoutPendingSource,
    uniqueness: defaults.uniqueness,
    renderError: defaults.renderError,
    interactionUrl: defaults.interactionUrl,
    interactionCheck: defaults.interactionCheck,
    audiences: defaults.audiences,
    findById: defaults.findById,
    postLogoutRedirectUri: defaults.postLogoutRedirectUri,
  }, (acc, value, key) => {
    if (typeof value === 'function') {
      acc[key] = () => value;
    } else {
      acc[key] = value;
    }
    return acc;
  }, {})),
  struct.interface({
    pairwiseSalt(value, { subjectTypes }) {
      if (!value && subjectTypes.includes('pairwise')) {
        return 'must be configured when pairwise subjectType is to be supported';
      }
      return true;
    },
  }),
]);
