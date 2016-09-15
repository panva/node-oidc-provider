'use strict';

const bootstrap = require('../test_helper');
const getMask = require('../../lib/helpers/claims');
const _ = require('lodash');
const { expect } = require('chai');
const nock = require('nock');

const j = JSON.stringify;


describe('pairwise features', () => {
  const { provider } = bootstrap(__dirname);
  const Claims = getMask(provider.configuration());


  describe('pairwise client configuration', () => {
    context('sector_identifier_uri is not provided', () => {
      it('resolves the sector_identifier from one redirect_uri', () => {
        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb'],
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client.sectorIdentifier).to.be.ok;
          expect(client.sectorIdentifier).to.eq('client.example.com');
        });
      });

      it('resolves the sector_identifier if redirect_uris hosts are the same', () => {
        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://client.example.com/forum/cb'],
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client.sectorIdentifier).to.be.ok;
          expect(client.sectorIdentifier).to.eq('client.example.com');
        });
      });

      it('fails to validate when multiple redirect_uris hosts are provided', () => {
        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://wrongsubdomain.example.com/forum/cb'],
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('sector_identifier_uri is required when using multiple hosts in your redirect_uris');
        });
      });
    });

    context('sector_identifier_uri is provided', () => {
      it('validates the sector from the provided uri', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .reply(200, j(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://another.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).to.be.ok;
          expect(client.sectorIdentifier).to.eq('client.example.com');
        }, (err) => {
          expect(err).not.to.be.ok;
        });
      });

      it('validates all redirect_uris are in the uri', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .reply(200, j(['https://client.example.com/cb', 'https://another.example.com/forum/cb']));

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('all registered redirect_uris must be included in the sector_identifier_uri');
        });
      });

      it('validates only accepts json array responses', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .reply(200, j('https://client.example.com/cb'));

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('sector_identifier_uri must return single JSON array');
        });
      });

      it('doesnt allow slow requests (socket delay)', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .socketDelay(100)
        .reply(200, j('https://client.example.com/cb'));

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.match(/could not load sector_identifier_uri \(Socket timed out on request to/);
        });
      });

      it('doesnt allow slow requests (response delay)', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .delay(100)
        .reply(200, j('https://client.example.com/cb'));

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.match(/could not load sector_identifier_uri \(Connection timed out on request to/);
        });
      });

      it('doesnt accepts 200s, rejects even on redirect', () => {
        nock('https://client.example.com/')
        .get('/file_of_redirect_uris')
        .reply(302, 'redirecting', {
          location: '/otherfile'
        });

        return provider.addClient({
          client_id: 'client',
          client_secret: 'secret',
          redirect_uris: ['https://client.example.com/cb', 'https://missing.example.com/forum/cb'],
          sector_identifier_uri: 'https://client.example.com/file_of_redirect_uris',
          subject_type: 'pairwise'
        }).then((client) => {
          expect(client).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err.message).to.eq('invalid_client_metadata');
          expect(err.error_description).to.eq('unexpected sector_identifier_uri statusCode, expected 200, got 302');
        });
      });
    });
  });

  describe('pairwise client Subject calls', () => {
    const clients = [];

    before(() => {
      return provider.addClient({
        client_id: 'clientOne',
        client_secret: 'secret',
        redirect_uris: ['https://clientone.com/cb'],
        subject_type: 'pairwise'
      }).then((client) => {
        clients.push(client);
      });
    });

    before(() => {
      return provider.addClient({
        client_id: 'clientTwo',
        client_secret: 'secret',
        redirect_uris: ['https://clienttwo.com/cb'],
        subject_type: 'pairwise'
      }).then((client) => {
        clients.push(client);
      });
    });

    before(() => {
      return provider.addClient({
        client_id: 'clientThree',
        client_secret: 'secret',
        redirect_uris: ['https://clientthree.com/cb']
      }).then((client) => {
        clients.push(client);
      });
    });

    it('returns different subs', () => {
      const subs = _.map(clients, (client) => {
        const { sub } = new Claims({ sub: 'accountId' }, client.sectorIdentifier).scope('openid').result();
        return sub;
      });

      expect(subs).to.have.lengthOf(3);
      expect(_.uniq(subs)).to.have.lengthOf(3);
      expect(subs).to.contain('accountId');
    });
  });
});
