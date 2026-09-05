import { expect } from 'chai';

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
  });

  function request(route, query = {}) {
    return { method: 'GET', query, oidc: { provider, route } };
  }

  it('reads enabled features and extra parameters for each authorization request', () => {
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
    expect(first.oidc.params.toPlainObject()).to.deep.equal({});

    for (const name of [
      'claimsParameter', 'dPoP', 'resourceIndicators',
      'richAuthorizationRequests', 'webMessageResponseMode',
    ]) configuration.features[name].enabled = true;
    configuration.extraParams.add('extension');

    const second = request('authorization', query);
    assembleAuthorizationParams(second, () => {});
    expect(second.oidc.params.toPlainObject()).to.deep.equal(query);

    configuration.extraParams.delete('extension');
    configuration.features.claimsParameter.enabled = false;

    const third = request('authorization', query);
    assembleAuthorizationParams(third, () => {});
    expect(third.oidc.params.toPlainObject()).not.to.have.any.keys('extension', 'claims');
  });

  it('retains endpoint restrictions after applying current extra parameters', () => {
    configuration.extraParams = new Set(['response_type', 'redirect_uri', 'prompt']);
    configuration.features.dPoP.enabled = true;
    const query = {
      response_type: 'code', redirect_uri: 'https://client.example.com', prompt: 'login',
      dpop_jkt: 'thumbprint', binding_message: 'message',
    };

    for (const route of ['device_authorization', 'code_verification', 'device_resume']) {
      const ctx = request(route, query);
      assembleAuthorizationParams(ctx, () => {});
      expect(ctx.oidc.params.toPlainObject()).to.deep.equal({});
    }

    const ctx = request('backchannel_authentication', query);
    assembleAuthorizationParams(ctx, () => {});
    expect(ctx.oidc.params.toPlainObject()).to.deep.equal({ binding_message: 'message' });
  });

  it('uses the current resource duplicate policy for request-object parameters', () => {
    const ctx = { oidc: { provider, params: { resource: ['urn:first', 'urn:second'] } } };
    expect(() => rejectAuthorizationDupes(ctx, () => {})).to.throw('invalid_request');

    configuration.features.resourceIndicators.enabled = true;
    ctx.oidc.params.resource = ['urn:first', 'urn:second'];
    rejectAuthorizationDupes(ctx, () => {});
    expect(ctx.oidc.params.resource).to.deep.equal(['urn:first', 'urn:second']);
  });

  it('reads the current client authentication methods', () => {
    const ctx = request('token');
    expect([...getClientAuthParams(ctx)]).to.deep.equal(['client_id']);

    configuration.clientAuthMethods.add('client_secret_post');
    configuration.clientAuthMethods.add('private_key_jwt');
    expect([...getClientAuthParams(ctx)]).to.deep.equal([
      'client_id', 'client_secret', 'client_assertion', 'client_assertion_type',
    ]);

    configuration.clientAuthMethods.delete('client_secret_post');
    expect(getClientAuthParams(ctx).has('client_secret')).to.equal(false);
  });
});
