'use strict';

const bootstrap = require('../test_helper');

describe('default error behavior', () => {
  const { agent } = bootstrap(__dirname);

  it('responds with json when no Accept header', () => {
    return agent.post('/me')
      .expect('content-type', /json/);
  });

  it('responds with json when */* header', () => {
    return agent.post('/me')
      .accept('*/*')
      .expect('content-type', /json/);
  });

  it('responds with html when browser like header', () => {
    return agent.post('/me')
      .accept('text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
      .expect('content-type', /html/);
  });
});
