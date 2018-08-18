const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('Client#add', () => {
  before(bootstrap(__dirname, { config: 'client_secrets' }));

  it('client secret is mandatory if even one of the authz needs it', function () {
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'none',
      revocation_endpoint_auth_method: 'none',
      introspection_endpoint_auth_method: 'client_secret_basic',
    })).to.be.true;
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'none',
      revocation_endpoint_auth_method: 'client_secret_basic',
      introspection_endpoint_auth_method: 'none',
    })).to.be.true;
    expect(this.provider.Client.needsSecret({
      token_endpoint_auth_method: 'client_secret_basic',
      revocation_endpoint_auth_method: 'none',
      introspection_endpoint_auth_method: 'none',
    })).to.be.true;
  });

  ['token', 'introspection', 'revocation'].forEach((endpoint) => {
    context(`configuring ${endpoint}_endpoint_auth_method=client_secret_jwt without ${endpoint}_endpoint_auth_signing_alg`, () => {
      it('validates the secret is long enough to support the top available alg bitsize', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'not64bytes_____________________________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [`${endpoint}_endpoint_auth_method`]: 'client_secret_jwt',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length (need at least 512 bits, got 504)');
        });
      });
    });
  });

  [
    'id_token_signed_response_alg',
    'request_object_signing_alg',
    'token_endpoint_auth_signing_alg',
    'revocation_endpoint_auth_signing_alg',
    'introspection_endpoint_auth_signing_alg',
    'userinfo_signed_response_alg',
    'introspection_signed_response_alg',
  ].forEach((metadata) => {
    context(`configuring ${metadata} when secrets are not long enough`, () => {
      it('validates the secret length (HS256)', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'not32bytes_____________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length (need at least 256 bits, got 248)');
        });
      });

      it('validates the secret length (HS384)', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'not48bytes_____________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length (need at least 384 bits, got 376)');
        });
      });

      it('validates the secret length (HS512)', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'not64bytes_____________________________________________________',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS512',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.have.property('message', 'invalid_client_metadata');
          expect(err).to.have.property('error_description', 'insufficient client_secret length (need at least 512 bits, got 504)');
        });
      });
    });

    context(`configuring ${metadata} when secrets are long enough`, () => {
      it('allows HS256', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'its32bytes_____________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS256',
        });
      });

      it('allows HS384', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'its48bytes_____________________________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS384',
        });
      });

      it('allows HS512', function () {
        return i(this.provider).clientAdd({
          client_id: `${Math.random()}`,
          client_secret: 'its64bytes_____________________________________________________!',
          redirect_uris: ['https://client.example.com/cb'],
          [metadata]: 'HS512',
        });
      });
    });
  });
});
