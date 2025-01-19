import { expect } from 'chai';
import nock from 'nock';

import bootstrap from '../../test_helper.js';
import request from '../../../lib/helpers/request.js';

describe('request helper', () => {
  before(bootstrap(import.meta.url));

  afterEach(nock.cleanAll);

  afterEach(() => {
    expect(nock.isDone()).to.be.true;
  });

  describe('when using custom httpOptions', () => {
    it('defaults to not sending the user-agent HTTP header', async function () {
      nock('https://www.example.com/', {
        badheaders: ['user-agent'],
      })
        .get('/')
        .reply(200);

      await request.call(this.provider, { url: 'https://www.example.com' });
    });

    it("uses a custom 'user-agent' HTTP header", async function () {
      nock('https://www.example.com/', {
        reqheaders: {
          'user-agent': 'some user agent',
        },
      })
        .get('/with-custom-user-agent')
        .reply(200);

      await request.call(this.provider, { url: 'https://www.example.com/with-custom-user-agent' });
    });
  });
});
