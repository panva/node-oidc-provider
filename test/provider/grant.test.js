import { expect } from 'chai';

import Provider from '../../lib/index.js';

describe('provider.Grant', () => {
  before(function () {
    this.Grant = new Provider('http://localhost').Grant;
  });

  it('manages OIDC Scope', function () {
    const grant = new this.Grant();
    expect(grant.getOIDCScope()).to.eql('');
    grant.addOIDCScope('openid');
    grant.addOIDCScope(['email']);
    grant.addOIDCScope(new Set(['profile']));
    expect(grant.getOIDCScope()).to.eql('openid email profile');
    grant.addOIDCScope('openid openid');
    grant.addOIDCScope(['email', 'email']);
    grant.addOIDCScope(new Set(['profile', 'profile']));
    expect(grant.getOIDCScope()).to.eql('openid email profile');
    grant.addOIDCScope('address');
    grant.rejectOIDCScope('email');
    grant.rejectOIDCScope(['profile']);
    grant.rejectOIDCScope(new Set(['address']));
    expect(grant.getOIDCScope()).to.eql('openid');
    expect(grant.getRejectedOIDCScope()).to.eql('email profile address');
    grant.rejectOIDCScope('phone');
    expect(grant.getOIDCScopeEncountered()).to.eql('openid email profile address phone');

    grant.rejected = undefined;

    expect(grant.getOIDCScopeFiltered(new Set(['email', 'profile']))).to.eql('email profile');
    expect(grant.getOIDCScopeFiltered(new Set(['email', 'profile', 'missing']))).to.eql('email profile');
    expect(grant.getOIDCScopeFiltered(['email', 'profile'])).to.eql('email profile');
    expect(grant.getOIDCScopeFiltered(['email', 'profile', 'missing'])).to.eql('email profile');
  });

  it('manages OIDC Claims', function () {
    const grant = new this.Grant();
    expect(grant.getOIDCClaims()).to.deep.eql([]);
    grant.addOIDCClaims(['sub']);
    grant.addOIDCClaims(['email']);
    grant.addOIDCClaims(new Set(['name']));
    expect(grant.getOIDCClaims()).to.deep.eql(['sub', 'email', 'name']);
    grant.addOIDCClaims(['sub', 'sub']);
    grant.addOIDCClaims(['email', 'email']);
    grant.addOIDCClaims(new Set(['name', 'name']));
    expect(grant.getOIDCClaims()).to.deep.eql(['sub', 'email', 'name']);
    grant.addOIDCClaims(['nickname']);
    grant.rejectOIDCClaims(['email']);
    grant.rejectOIDCClaims(['name']);
    grant.rejectOIDCClaims(new Set(['nickname']));
    expect(grant.getOIDCClaims()).to.deep.eql(['sub']);
    expect(grant.getRejectedOIDCClaims()).to.deep.eql(['email', 'name', 'nickname']);
    grant.rejectOIDCClaims(['phone']);
    expect(grant.getOIDCClaimsEncountered()).to.deep.eql(['sub', 'email', 'name', 'nickname', 'phone']);

    grant.rejected = undefined;

    expect(grant.getOIDCClaimsFiltered(new Set(['email', 'name']))).to.deep.eql(['email', 'name']);
    expect(grant.getOIDCClaimsFiltered(new Set(['email', 'name', 'missing']))).to.deep.eql(['email', 'name']);
    expect(grant.getOIDCClaimsFiltered(['email', 'name'])).to.deep.eql(['email', 'name']);
    expect(grant.getOIDCClaimsFiltered(['email', 'name', 'missing'])).to.deep.eql(['email', 'name']);
  });

  it('manages Resource Scope', function () {
    const grant = new this.Grant();
    const resource = 'urn:example:rs';
    expect(grant.getResourceScope(resource)).to.eql('');
    grant.addResourceScope(resource, 'read');
    grant.addResourceScope(resource, ['create']);
    grant.addResourceScope(resource, new Set(['delete']));
    expect(grant.getResourceScope(resource)).to.eql('read create delete');
    grant.addResourceScope(resource, 'read read');
    grant.addResourceScope(resource, ['create', 'create']);
    grant.addResourceScope(resource, new Set(['delete', 'delete']));
    expect(grant.getResourceScope(resource)).to.eql('read create delete');
    grant.addResourceScope(resource, 'update');
    grant.rejectResourceScope(resource, 'create');
    grant.rejectResourceScope(resource, ['delete']);
    grant.rejectResourceScope(resource, new Set(['update']));
    expect(grant.getResourceScope(resource)).to.eql('read');
    expect(grant.getRejectedResourceScope(resource)).to.eql('create delete update');
    grant.rejectResourceScope(resource, 'phone');
    expect(grant.getResourceScopeEncountered(resource)).to.eql('read create delete update phone');

    grant.rejected = undefined;

    expect(grant.getResourceScopeFiltered(resource, new Set(['create', 'delete']))).to.eql('create delete');
    expect(grant.getResourceScopeFiltered(resource, new Set(['create', 'delete', 'missing']))).to.eql('create delete');
    expect(grant.getResourceScopeFiltered(resource, ['create', 'delete'])).to.eql('create delete');
    expect(grant.getResourceScopeFiltered(resource, ['create', 'delete', 'missing'])).to.eql('create delete');
  });
});
