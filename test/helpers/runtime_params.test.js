import { describe, beforeEach, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  assembleAuthorizationParams,
  rejectAuthorizationDupes,
} from '../../lib/actions/authorization/request_parameters.js';
import Provider from '../../lib/index.js';
import instance from '../../lib/helpers/weak_cache.js';
import { getClientAuthParams } from '../../lib/shared/client_auth.js';

describe('runtime request parameters', () => {
  let provider;
  let configuration;

  beforeEach(() => {
    provider = new Provider('https://op.example.com', { clientAuthMethods: ['none'] });
    configuration = instance(provider).configuration;
    for (const name of [
      'claimsParameter', 'dPoP', 'resourceIndicators',
      'richAuthorizationRequests', 'webMessageResponseMode',
    ]) configuration.features[name].enabled = false;
  }, { timeout: 3000 });

  function request(route, query = {}) {
    return { method: 'GET', query, oidc: { provider, route } };
  }

  it('reads enabled features and extra parameters for each authorization request', { timeout: 3000 }, () => {
    const query = {
      claims: '{}',
      dpop_jkt: 'thumbprint',
      resource: 'https://api.example.com',
      authorization_details: '[]',
      web_message_uri: 'https://client.example.com',
      extension: 'value',
    };
    const first = request('authorization', query);
    assembleAuthorizationParams(first, () => {});
    assert.deepEqual(first.oidc.params.toPlainObject(), {});

    for (const name of [
      'claimsParameter', 'dPoP', 'resourceIndicators',
      'richAuthorizationRequests', 'webMessageResponseMode',
    ]) configuration.features[name].enabled = true;
    configuration.extraParams.add('extension');

    const second = request('authorization', query);
    assembleAuthorizationParams(second, () => {});
    assert.deepEqual(second.oidc.params.toPlainObject(), query);

    configuration.extraParams.delete('extension');
    configuration.features.claimsParameter.enabled = false;

    const third = request('authorization', query);
    assembleAuthorizationParams(third, () => {});
    assert.ok(!(['extension', 'claims'].some((key) => Object.keys(third.oidc.params.toPlainObject()).includes(key))));
  });

  it('retains endpoint restrictions after applying current extra parameters', { timeout: 3000 }, () => {
    configuration.extraParams = new Set(['response_type', 'redirect_uri', 'prompt']);
    configuration.features.dPoP.enabled = true;
    const query = {
      response_type: 'code', redirect_uri: 'https://client.example.com', prompt: 'login',
      dpop_jkt: 'thumbprint', binding_message: 'message',
    };

    for (const route of ['device_authorization', 'code_verification', 'device_resume']) {
      const ctx = request(route, query);
      assembleAuthorizationParams(ctx, () => {});
      assert.deepEqual(ctx.oidc.params.toPlainObject(), {});
    }

    const ctx = request('backchannel_authentication', query);
    assembleAuthorizationParams(ctx, () => {});
    assert.deepEqual(ctx.oidc.params.toPlainObject(), { binding_message: 'message' });
  });

  it('uses the current resource duplicate policy for request-object parameters', { timeout: 3000 }, () => {
    const ctx = { oidc: { provider, params: { resource: ['urn:first', 'urn:second'] } } };
    assert.throws(() => rejectAuthorizationDupes(ctx, () => {}), (error) => { assert.ok(error.message.includes('invalid_request')); return true; });

    configuration.features.resourceIndicators.enabled = true;
    ctx.oidc.params.resource = ['urn:first', 'urn:second'];
    rejectAuthorizationDupes(ctx, () => {});
    assert.deepEqual(ctx.oidc.params.resource, ['urn:first', 'urn:second']);
  });

  it('reads the current client authentication methods', { timeout: 3000 }, () => {
    const ctx = request('token');
    assert.deepEqual([...getClientAuthParams(ctx)], ['client_id']);

    configuration.clientAuthMethods.add('client_secret_post');
    configuration.clientAuthMethods.add('private_key_jwt');
    assert.deepEqual([...getClientAuthParams(ctx)], [
      'client_id', 'client_secret', 'client_assertion', 'client_assertion_type',
    ]);

    configuration.clientAuthMethods.delete('client_secret_post');
    assert.equal(getClientAuthParams(ctx).has('client_secret'), false);
  });
});
