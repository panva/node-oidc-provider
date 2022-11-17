const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('registration management with client_id as URI', () => {
  before(bootstrap(__dirname));

  it('returns client_id as a URI string', async function () {
    let client_id;
    let registration_client_uri;
    let registration_access_token;

    await this.agent.post('/reg')
      .send({
        redirect_uris: ['https://client.example.com/cb'],
      })
      .expect(201)
      .expect((response) => {
        ({ client_id, registration_access_token, registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        expect(parsed.search).to.be.empty;
        const i = parsed.pathname.indexOf('/reg/');
        expect(parsed.pathname.slice(i + 5)).to.equal(encodeURIComponent(client_id));
      });

    await this.agent.get(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .expect(200)
      .expect((response) => {
        ({ registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        expect(parsed.search).to.be.empty;
        const i = parsed.pathname.indexOf('/reg/');
        expect(parsed.pathname.slice(i + 5)).to.equal(encodeURIComponent(client_id));
      });

    await this.agent.put(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .send({
        client_id,
        redirect_uris: ['https://client.example.com/cb2'],
      })
      .expect(200)
      .expect((response) => {
        ({ registration_client_uri } = response.body);

        const parsed = new URL(registration_client_uri);
        expect(parsed.search).to.be.empty;
        const i = parsed.pathname.indexOf('/reg/');
        expect(parsed.pathname.slice(i + 5)).to.equal(encodeURIComponent(client_id));
      });

    await this.agent.delete(new URL(registration_client_uri).pathname)
      .auth(registration_access_token, { type: 'bearer' })
      .expect(204);
  });
});
