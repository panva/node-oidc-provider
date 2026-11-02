import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import map from 'lodash/map.js';
import uniq from 'lodash/uniq.js';

import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';
import addClient from '../../lib/helpers/add_client.js';

describe('pairwise features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  afterEach(() => assertNoPendingInterceptors(), { timeout: 3000 });

  describe('pairwise client configuration', () => {
    const fixture1 = Object.create(fixture);

    describe('sector_identifier_uri is not provided', () => {
      const fixture2 = Object.create(fixture1);

      it('resolves the sector_identifier from one redirect_uri', { timeout: 3000 }, () => addClient(fixture2.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(client.sectorIdentifier);
          assert.equal(client.sectorIdentifier, 'client.example.com');
        }));

      it('resolves the sector_identifier if redirect_uris hosts are the same', { timeout: 3000 }, () => addClient(fixture2.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://client.example.com/forum/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(client.sectorIdentifier);
          assert.equal(client.sectorIdentifier, 'client.example.com');
        }));

      it('fails to validate when multiple redirect_uris hosts are provided', { timeout: 3000 }, () => addClient(fixture2.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://wrongsubdomain.example.com/forum/cb'],
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'sector_identifier_uri is mandatory property');
        }));
    });

    describe('sector_identifier_uri is provided', () => {
      const fixture3 = Object.create(fixture1);

      it('is not ignored even without subject_type=pairwise', { timeout: 3000 }, () => {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'https://foobar.example.com/sector',
          subject_type: 'public',
        }).then((client) => {
          assert.ok(client);
          assert.equal(client.sectorIdentifier, 'foobar.example.com');
        });
      });

      it('validates the sector from the provided uri', { timeout: 3000 }, () => {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'https://foobar.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(client);
          assert.equal(client.sectorIdentifier, 'foobar.example.com');
        });
      });

      it('validates the sector from the provided uri for static clients too', { timeout: 3000 }, () => {
        mock('https://foobar.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return fixture3.provider.Client.find('client-static-with-sector').then((client) => {
          assert.ok(client);
          assert.equal(client.sectorIdentifier, 'foobar.example.com');
        });
      });

      it('must be an https uri', { timeout: 3000 }, () => addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'http://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'sector_identifier_uri must be a https uri');
        }));

      it('validates all redirect_uris are in the uri', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'all registered redirect_uris must be included in the sector_identifier_uri response');
        });
      });

      describe('features.ciba', () => {
        const fixture4 = Object.create(fixture3);

        it('validates jwks_uri is in the response', { timeout: 3000 }, () => {
          mock('https://client.example.com')
            .intercept({
              path: '/sector',
            })
            .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

          return addClient(fixture4.provider, {
            client_id: 'client',
            response_types: [],
            backchannel_token_delivery_mode: 'poll',
            grant_types: ['urn:openid:params:grant-type:ciba'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://client.example.com/jwks',
            sector_identifier_uri: 'https://client.example.com/sector',
            subject_type: 'pairwise',
          }).then((client) => {
            assert.ok(!(client));
          }, (err) => {
            assert.ok(err);
            assert.equal(err.message, 'invalid_client_metadata');
            assert.equal(err.error_description, "client's jwks_uri must be included in the sector_identifier_uri response");
          });
        });
      });

      describe('features.deviceFlow', () => {
        const fixture5 = Object.create(fixture3);

        it('validates jwks_uri is in the response', { timeout: 3000 }, () => {
          mock('https://client.example.com')
            .intercept({
              path: '/sector',
            })
            .reply(200, JSON.stringify(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

          return addClient(fixture5.provider, {
            client_id: 'client',
            response_types: [],
            grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks_uri: 'https://client.example.com/jwks',
            sector_identifier_uri: 'https://client.example.com/sector',
            subject_type: 'pairwise',
          }).then((client) => {
            assert.ok(!(client));
          }, (err) => {
            assert.ok(err);
            assert.equal(err.message, 'invalid_client_metadata');
            assert.equal(err.error_description, "client's jwks_uri must be included in the sector_identifier_uri response");
          });
        });
      });

      it('validates the response is a json', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, '{ not a valid json');

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'failed to parse sector_identifier_uri JSON response');
        });
      });

      it('validates only accepts json array responses', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify('https://client.example.com/cb'));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'sector_identifier_uri must return single JSON array');
        });
      });

      it('rejects non-string sector identifier document members', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(200, JSON.stringify(['https://client.example.com/cb', null]));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'sector_identifier_uri must return an array of redirect_uri values');
        });
      });

      it('handles got lib errors', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(500);

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'unexpected sector_identifier_uri response status code, expected 200 OK, got 500 Internal Server Error');
        });
      });

      it('doesnt accepts 200s, rejects even on redirect', { timeout: 3000 }, () => {
        mock('https://client.example.com')
          .intercept({
            path: '/sector',
          })
          .reply(201, JSON.stringify('https://client.example.com/cb'));

        return addClient(fixture3.provider, {
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/sector',
          subject_type: 'pairwise',
        }).then((client) => {
          assert.ok(!(client));
        }, (err) => {
          assert.ok(err);
          assert.equal(err.message, 'invalid_client_metadata');
          assert.equal(err.error_description, 'unexpected sector_identifier_uri response status code, expected 200 OK, got 201 Created');
        });
      });
    });
  });

  describe('pairwise client Subject calls', () => {
    const fixture6 = Object.create(fixture);

    const clients = [];

    before(() => addClient(fixture6.provider, {
        client_id: 'clientOne',
        client_secret: 'secret',
        redirect_uris: ['https://clientone.com/cb'],
        subject_type: 'pairwise',
      }).then((client) => {
        clients.push(client);
      }), { timeout: 3000 });

    before(() => addClient(fixture6.provider, {
        client_id: 'clientTwo',
        client_secret: 'secret',
        redirect_uris: ['https://clienttwo.com/cb'],
        subject_type: 'pairwise',
      }).then((client) => {
        clients.push(client);
      }), { timeout: 3000 });

    before(() => addClient(fixture6.provider, {
        client_id: 'clientThree',
        client_secret: 'secret',
        redirect_uris: ['https://clientthree.com/cb'],
      }).then((client) => {
        clients.push(client);
      }), { timeout: 3000 });

    it('returns different subs', { timeout: 3000 }, async () => {
      const subs = await Promise.all(map(clients, async (client) => {
        const claims = new fixture6.provider.Claims({ sub: 'accountId' }, { client, ctx: undefined });
        claims.scope('openid');

        const { sub } = await claims.result();
        return sub;
      }));

      assert.equal(subs.length, 3);
      assert.equal(uniq(subs).length, 3);
      assert.ok(subs.includes('accountId'));
    });
  });
});
