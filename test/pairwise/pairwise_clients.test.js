import map from 'lodash/map.js';
import uniq from 'lodash/uniq.js';
import { expect } from 'chai';

import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';
import addClient from '../../lib/helpers/add_client.js';

describe('pairwise features', () => {
  before(bootstrap(import.meta.url));

  afterEach(assertNoPendingInterceptors);

  describe('pairwise client configuration', () => {
    context('sector_identifier_uri is not provided', () => {
      it('resolves the sector_identifier from one redirect_uri', function () {
        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client.sectorIdentifier).to.be.ok;
          expect(client.sectorIdentifier).to.eq('client.example.com');
        });
      });

      it('resolves the sector_identifier if redirect_uris hosts are the same', function () {
        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://client.example.com/forum/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client.sectorIdentifier).to.be.ok;
          expect(client.sectorIdentifier).to.eq('client.example.com');
        });
      });

      it('fails to validate when multiple redirect_uris hosts are provided', function () {
        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://wrongsubdomain.example.com/forum/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('sector_identifier_uri is mandatory property');
        });
      });
    });

    context('sector_identifier_uri is provided', () => {
      it('is not ignored even without subject_type=pairwise', function () {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'https://foobar.example.com/sector',
          subject_type: 'public',
        }).then((client) => {
          expect(client).to.be.ok;
          expect(client.sectorIdentifier).to.eq('foobar.example.com');
        });
      });

      it('validates the sector from the provided uri', function () {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'https://foobar.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).to.be.ok;
          expect(client.sectorIdentifier).to.eq('foobar.example.com');
        });
      });

      it('validates the sector from the provided uri for static clients too', function () {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return this.provider.Client.find('client-static-with-sector').then((client) => {
          expect(client).to.be.ok;
          expect(client.sectorIdentifier).to.eq('foobar.example.com');
        });
      });

      it('must be an https uri', function () {
        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'http://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err.message).to.equal('invalid_client_metadata');
          expect(err.error_description).to.equal('sector_identifier_uri must be a https uri');
        });
      });

      it('validates all redirect_uris are in the uri', function () {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('all registered redirect_uris must be included in the sector_identifier_uri response');
        });
      });

      describe('features.ciba', () => {
        it('validates jwks_uri is in the response', function () {
          mock('https://client.example.com')
            .intercept({
              path: '/sector',
            })
            .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

          return addClient(this.provider, {
            client_id: 'client',
            response_types: [],
            backchannel_token_delivery_mode: 'poll',
            grant_types: ['urn:openid:params:grant-type:ciba'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://client.example.com/jwks',
            sector_identifier_uri: 'https://client.example.com/sector',
            subject_type: 'pairwise',
          }).then((client) => {
            expect(client).not.to.be.ok;
          }, (err) => {
            expect(err).to.be.ok;
            expect(err.message).to.eq('invalid_client_metadata');
            expect(err.error_description).to.eq("client's jwks_uri must be included in the sector_identifier_uri response");
          });
        });
      });

      describe('features.deviceFlow', () => {
        it('validates jwks_uri is in the response', function () {
          mock('https://client.example.com')
            .intercept({
              path: '/sector',
            })
            .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

          return addClient(this.provider, {
            client_id: 'client',
            response_types: [],
            grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://client.example.com/jwks',
            sector_identifier_uri: 'https://client.example.com/sector',
            subject_type: 'pairwise',
          }).then((client) => {
            expect(client).not.to.be.ok;
          }, (err) => {
            expect(err).to.be.ok;
            expect(err.message).to.eq('invalid_client_metadata');
            expect(err.error_description).to.eq("client's jwks_uri must be included in the sector_identifier_uri response");
          });
        });
      });

      it('validates the response is a json', function () {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, '{ not a valid json');

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('failed to parse sector_identifier_uri JSON response');
        });
      });

      it('validates only accepts json array responses', function () {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify('https://client.example.com/cb'));

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('sector_identifier_uri must return single JSON array');
        });
      });

      it('handles got lib errors', function () {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(500);

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('unexpected sector_identifier_uri response status code, expected 200 OK, got 500 Internal Server Error');
        });
      });

      it('doesnt accepts 200s, rejects even on redirect', function () {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(201, JSON.stringify('https://client.example.com/cb'));

        return addClient(this.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('unexpected sector_identifier_uri response status code, expected 200 OK, got 201 Created');
        });
      });
    });
  });

  describe('pairwise client Subject calls', () => {
    const clients = [];

    before(function () {
      return addClient(this.provider, {
        client_id: 'clientOne',
        client_secret: 'secret',
        redirect_uris: ['https://clientone.com/cb'],
        subject_type: 'pairwise',
      }).then((client) => {
        clients.push(client);
      });
    });

    before(function () {
      return addClient(this.provider, {
        client_id: 'clientTwo',
        client_secret: 'secret',
        redirect_uris: ['https://clienttwo.com/cb'],
        subject_type: 'pairwise',
      }).then((client) => {
        clients.push(client);
      });
    });

    before(function () {
      return addClient(this.provider, {
        client_id: 'clientThree',
        client_secret: 'secret',
        redirect_uris: ['https://clientthree.com/cb'],
      }).then((client) => {
        clients.push(client);
      });
    });

    it('returns different subs', async function () {
      const subs = await Promise.all(map(clients, async (client) => {
        const claims = new this.provider.Claims({ sub: 'accountId' }, { client, ctx: undefined });
        claims.scope('openid');

        const { sub } = await claims.result();
        return sub;
      }));

      expect(subs).to.have.lengthOf(3);
      expect(uniq(subs)).to.have.lengthOf(3);
      expect(subs).to.contain('accountId');
    });
  });
});
