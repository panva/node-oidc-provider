const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/jwks';

describe(route, () => {
  before(bootstrap(__dirname));

  describe('when populated with signing keys', () => {
    it('responds with json 200', function () {
      return this.agent.get(route)
        .expect('Content-Type', /application\/json/)
        .expect(200)
        .expect((res) => {
          let rsa;
          let ec;
          let okp;

          expect(res.body.keys.length).to.equal(global.keystore.size);

          res.body.keys.forEach((key) => {
            if (key.kty === 'RSA') rsa = key;
            if (key.kty === 'EC') ec = key;
            if (key.kty === 'OKP') okp = key;
          });

          expect(rsa).to.be.ok;
          expect(ec).to.be.ok;
          if (okp) expect(okp).to.be.ok;

          expect(rsa).to.have.all.keys(['kty', 'kid', 'e', 'n']);
          expect(ec).to.have.all.keys(['kty', 'kid', 'crv', 'x', 'y']);
          if (okp) expect(okp).to.have.all.keys(['kty', 'kid', 'crv', 'x']);
        });
    });

    it('does not populate ctx.oidc.entities', function (done) {
      this.provider.use(this.assertOnce((ctx) => {
        expect(ctx.oidc.entities).to.be.empty;
      }, done));

      this.agent.get(route).end(() => {});
    });
  });
});
