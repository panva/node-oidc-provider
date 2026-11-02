import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import Provider from '../../lib/index.js';

describe('provider.Grant', () => {
  const fixture = {};

  before(() => {
    fixture.Grant = new Provider('http://localhost').Grant;
  }, { timeout: 3000 });

  it('manages OIDC Scope', { timeout: 3000 }, () => {
    const grant = new fixture.Grant();
    assert.deepEqual(grant.getOIDCScope(), '');
    grant.addOIDCScope('openid');
    grant.addOIDCScope(['email']);
    grant.addOIDCScope(new Set(['profile']));
    assert.deepEqual(grant.getOIDCScope(), 'openid email profile');
    grant.addOIDCScope('openid openid');
    grant.addOIDCScope(['email', 'email']);
    grant.addOIDCScope(new Set(['profile', 'profile']));
    assert.deepEqual(grant.getOIDCScope(), 'openid email profile');
    grant.addOIDCScope('address');
    grant.rejectOIDCScope('email');
    grant.rejectOIDCScope(['profile']);
    grant.rejectOIDCScope(new Set(['address']));
    assert.deepEqual(grant.getOIDCScope(), 'openid');
    assert.deepEqual(grant.getRejectedOIDCScope(), 'email profile address');
    grant.rejectOIDCScope('phone');
    assert.deepEqual(grant.getOIDCScopeEncountered(), 'openid email profile address phone');

    grant.rejected = undefined;

    assert.deepEqual(grant.getOIDCScopeFiltered(new Set(['email', 'profile'])), 'email profile');
    assert.deepEqual(grant.getOIDCScopeFiltered(new Set(['email', 'profile', 'missing'])), 'email profile');
    assert.deepEqual(grant.getOIDCScopeFiltered(['email', 'profile']), 'email profile');
    assert.deepEqual(grant.getOIDCScopeFiltered(['email', 'profile', 'missing']), 'email profile');
  });

  it('manages OIDC Claims', { timeout: 3000 }, () => {
    const grant = new fixture.Grant();
    assert.deepEqual(grant.getOIDCClaims(), []);
    grant.addOIDCClaims(['sub']);
    grant.addOIDCClaims(['email']);
    grant.addOIDCClaims(new Set(['name']));
    assert.deepEqual(grant.getOIDCClaims(), ['sub', 'email', 'name']);
    grant.addOIDCClaims(['sub', 'sub']);
    grant.addOIDCClaims(['email', 'email']);
    grant.addOIDCClaims(new Set(['name', 'name']));
    assert.deepEqual(grant.getOIDCClaims(), ['sub', 'email', 'name']);
    grant.addOIDCClaims(['nickname']);
    grant.rejectOIDCClaims(['email']);
    grant.rejectOIDCClaims(['name']);
    grant.rejectOIDCClaims(new Set(['nickname']));
    assert.deepEqual(grant.getOIDCClaims(), ['sub']);
    assert.deepEqual(grant.getRejectedOIDCClaims(), ['email', 'name', 'nickname']);
    grant.rejectOIDCClaims(['phone']);
    assert.deepEqual(grant.getOIDCClaimsEncountered(), ['sub', 'email', 'name', 'nickname', 'phone']);

    grant.rejected = undefined;

    assert.deepEqual(grant.getOIDCClaimsFiltered(new Set(['email', 'name'])), ['email', 'name']);
    assert.deepEqual(grant.getOIDCClaimsFiltered(new Set(['email', 'name', 'missing'])), ['email', 'name']);
    assert.deepEqual(grant.getOIDCClaimsFiltered(['email', 'name']), ['email', 'name']);
    assert.deepEqual(grant.getOIDCClaimsFiltered(['email', 'name', 'missing']), ['email', 'name']);
  });

  it('manages Resource Scope', { timeout: 3000 }, () => {
    const grant = new fixture.Grant();
    const resource = 'urn:example:rs';
    assert.deepEqual(grant.getResourceScope(resource), '');
    grant.addResourceScope(resource, 'read');
    grant.addResourceScope(resource, ['create']);
    grant.addResourceScope(resource, new Set(['delete']));
    assert.deepEqual(grant.getResourceScope(resource), 'read create delete');
    grant.addResourceScope(resource, 'read read');
    grant.addResourceScope(resource, ['create', 'create']);
    grant.addResourceScope(resource, new Set(['delete', 'delete']));
    assert.deepEqual(grant.getResourceScope(resource), 'read create delete');
    grant.addResourceScope(resource, 'update');
    grant.rejectResourceScope(resource, 'create');
    grant.rejectResourceScope(resource, ['delete']);
    grant.rejectResourceScope(resource, new Set(['update']));
    assert.deepEqual(grant.getResourceScope(resource), 'read');
    assert.deepEqual(grant.getRejectedResourceScope(resource), 'create delete update');
    grant.rejectResourceScope(resource, 'phone');
    assert.deepEqual(grant.getResourceScopeEncountered(resource), 'read create delete update phone');

    grant.rejected = undefined;

    assert.deepEqual(grant.getResourceScopeFiltered(resource, new Set(['create', 'delete'])), 'create delete');
    assert.deepEqual(grant.getResourceScopeFiltered(resource, new Set(['create', 'delete', 'missing'])), 'create delete');
    assert.deepEqual(grant.getResourceScopeFiltered(resource, ['create', 'delete']), 'create delete');
    assert.deepEqual(grant.getResourceScopeFiltered(resource, ['create', 'delete', 'missing']), 'create delete');
  });
});
