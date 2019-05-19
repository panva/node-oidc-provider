const { expect } = require('chai');
const cors = require('@koa/cors');

const bootstrap = require('../test_helper');

function req(verb, url, origin, ...methods) {
  const request = this.agent[verb](url)
    .set('Origin', origin);

  if (methods.length) {
    methods.forEach(([method, ...args]) => {
      request[method](...args);
    });
  }

  return request;
}

function preflight(verb, url, origin) {
  return this.agent.options(url)
    .set('Access-Control-Request-Method', verb)
    .set('Origin', origin);
}

const ACAMaxAge = 'access-control-max-age';
const ACAOrigin = 'access-control-allow-origin';

describe('CORS setup', () => {
  before(bootstrap(__dirname));

  before(async function () {
    this.provider.use(cors({
      origin: 'https://example.com',
    }));
  });

  it('ignores all built-in cors then', async function () {
    let { status, headers } = await preflight.call(this, 'GET', '/.well-known/openid-configuration', 'https://rp.example.com');
    expect(status).to.eql(204);
    expect(headers[ACAOrigin]).to.eql('https://example.com');
    expect(headers).not.to.have.property(ACAMaxAge);

    ({ status, headers } = await req.call(
      this,
      'get',
      '/.well-known/openid-configuration',
      'https://rp.example.com',
    ));
    expect(status).to.eql(200);
    expect(headers[ACAOrigin]).to.eql('https://example.com');
    expect(headers).not.to.have.property(ACAMaxAge);
  });
});
