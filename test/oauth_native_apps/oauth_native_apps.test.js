'use strict';

const bootstrap = require('../test_helper');


describe('OAuth 2.0 for Native Apps Best Current Practice features', function () {
  before(bootstrap(__dirname)); // provider

  describe('changed native client validations', function () {
    describe('App-declared Custom URI Scheme Redirection', function () {
      it('allows custom uri scheme uris with localhost');
      it('rejects custom uri scheme uris if not using localhost');
    });

    describe('App-claimed HTTPS URI Redirection', function () {
      it('allows claimed https uris');
      it('rejects https if using loopback uris');
    });

    describe('Loopback URI Redirection', function () {
      it('allows http protocol localhost loopback uris');
      it('allows http protocol IPv4 loopback uris');
      it('allows http protocol IPv6 loopback uris');
      it('rejects http protocol uris not using loopback uris');
    });
  });

  describe('authentication request validations', function () {
    it('allows Loopback URI Redirection to provide a random port value');
  });
});
