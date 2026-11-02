import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';


import bootstrap from '../test_helper.js';
import addClient from '../../lib/helpers/add_client.js';

describe('OAuth 2.0 for Native Apps Best Current Practice features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('changed native client validations', () => {
    const fixture1 = Object.create(fixture);

    describe('Loopback Interface Redirection', () => {
      const fixture2 = Object.create(fixture1);

      it('catches invalid urls being passed in', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1:2355/op/logout'],
        }).then((client) => {
          assert.equal(client.redirectUriAllowed('http:'), false);
          assert.equal(client.redirectUriAllowed('http://127.0.0.'), false);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1::'), false);
          assert.equal(client.postLogoutRedirectUriAllowed('http:'), false);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.'), false);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1::'), false);
        }));

      it('matches every raw loopback URI component except the port', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-exact-loopback',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: [
            'http://localhost:2355/op/callback',
            'http://127.0.0.1:2355/op/callback',
            'http://user:pass@localhost/op/callback',
          ],
          post_logout_redirect_uris: [
            'http://localhost:2355/op/logout',
            'http://127.0.0.1:2355/op/logout',
            'http://user:pass@localhost/op/logout',
          ],
        }).then((client) => {
          assert.equal(client.redirectUriAllowed('http://localhost:8888/op/callback'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:8888/op/logout'), true);
          assert.equal(client.redirectUriAllowed('http://user:pass@localhost:8888/op/callback'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://user:pass@localhost:8888/op/logout'), true);

          for (const redirectUri of [
            'HTTP://localhost:8888/op/callback',
            'http://LOCALHOST:8888/op/callback',
            'http://127.000.000.001:8888/op/callback',
            'http://127.0.0.1:8888/op/x/../callback',
          ]) {
            assert.equal(client.redirectUriAllowed(redirectUri), false);
          }

          for (const postLogoutRedirectUri of [
            'HTTP://localhost:8888/op/logout',
            'http://LOCALHOST:8888/op/logout',
            'http://127.000.000.001:8888/op/logout',
            'http://127.0.0.1:8888/op/x/../logout',
          ]) {
            assert.equal(client.postLogoutRedirectUriAllowed(postLogoutRedirectUri), false);
          }
        }));

      it('allows http protocol localhost loopback uris (when registered with a random port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost:2355/op/callback'],
          post_logout_redirect_uris: ['http://localhost:2355/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://localhost:2355/op/callback'));
          assert.equal(client.redirectUriAllowed('http://localhost/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://localhost:2355/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:8888/op/logout'), true);
        }));

      it('allows http protocol localhost loopback uris (when registered without a port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost/op/callback'],
          post_logout_redirect_uris: ['http://localhost/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://localhost/op/callback'));
          assert.equal(client.redirectUriAllowed('http://localhost/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://localhost:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://localhost/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://localhost:8888/op/logout'), true);
        }));

      it('allows http protocol IPv4 loopback uris (when registered with a random port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1:2355/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1:2355/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://127.0.0.1:2355/op/callback'));
          assert.equal(client.redirectUriAllowed('http://127.0.0.1/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://127.0.0.1:2355/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:8888/op/logout'), true);
        }));

      it('allows http protocol IPv4 loopback uris (when registered without a port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://127.0.0.1/op/callback'],
          post_logout_redirect_uris: ['http://127.0.0.1/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://127.0.0.1/op/callback'));
          assert.equal(client.redirectUriAllowed('http://127.0.0.1/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://127.0.0.1:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://127.0.0.1/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://127.0.0.1:8888/op/logout'), true);
        }));

      it('allows http protocol IPv6 loopback uris (when registered with a random port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]:2355/op/callback'],
          post_logout_redirect_uris: ['http://[::1]:2355/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://[::1]:2355/op/callback'));
          assert.equal(client.redirectUriAllowed('http://[::1]/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://[::1]:2355/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:8888/op/logout'), true);
        }));

      it('allows http protocol IPv6 loopback uris (when registered without a port)', { timeout: 3000 }, () => addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]/op/callback'],
          post_logout_redirect_uris: ['http://[::1]/op/logout'],
        }).then((client) => {
          assert.ok(client.redirectUris.includes('http://[::1]/op/callback'));
          assert.equal(client.redirectUriAllowed('http://[::1]/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:80/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:443/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:2355/op/callback'), true);
          assert.equal(client.redirectUriAllowed('http://[::1]:8888/op/callback'), true);

          assert.ok(client.postLogoutRedirectUris.includes('http://[::1]/op/logout'));
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:80/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:443/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:2355/op/logout'), true);
          assert.equal(client.postLogoutRedirectUriAllowed('http://[::1]:8888/op/logout'), true);
        }));

      it('rejects http protocol redirect_uris not using loopback uris', { timeout: 3000 }, () => assert.rejects(addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://rp.example.com/op/callback'],
        }), (err) => {
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_redirect_uri'); })(err);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'redirect_uris for native clients using http as a protocol can only use loopback addresses as hostnames'); })(err);
          return true;
        }));

      it('rejects http protocol post_logout_redirect_uris not using loopback uris', { timeout: 3000 }, () => assert.rejects(addClient(fixture2.provider, {
          application_type: 'native',
          client_id: 'native-custom',
          grant_types: ['implicit'],
          response_types: ['id_token'],
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://[::1]/op/callback'],
          post_logout_redirect_uris: ['http://rp.example.com/op/logout'],
        }), (err) => {
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_client_metadata'); })(err);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'post_logout_redirect_uris for native clients using http as a protocol can only use loopback addresses as hostnames'); })(err);
          return true;
        }));
    });
  });
});
