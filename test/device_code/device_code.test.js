import { expect } from 'chai';

import Provider from '../../lib/index.js';
import bootstrap from '../test_helper.js';

describe('configuration features.deviceFlow', () => {
  before(bootstrap(import.meta.url));

  it('can only be configured with digits and base-20 charset', () => {
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'digits',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'base-20',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            charset: 'foo',
          },
        },
      });
    }).to.throw('only supported charsets are "base-20" and "digits"');
  });

  it('can be configured with a mask', () => {
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            mask: '*** *** ***',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            mask: '***-***-***',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', { // eslint-disable-line no-new
        features: {
          deviceFlow: {
            enabled: true,
            mask: '***.***.***',
          },
        },
      });
    }).to.throw('mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters');
  });

  it('can be configured with a confirmParamName', () => {
    expect(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            confirmParamName: 'approved',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            confirmParamName: 'accept_request',
          },
        },
      });
    }).not.to.throw;
    expect(() => {
      new Provider('http://localhost', {
        features: {
          deviceFlow: {
            enabled: true,
            confirmParamName: 'abc+12',
          },
        },
      });
    }).to.throw('confirmation parameter name needs to be 1 - 20 characters in length and use only a basic set of characters (matching the regex: ^[a-zA-Z0-9_]{1,20}$ )');
  });

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.contain.keys('device_authorization_endpoint');
      });
  });
});
