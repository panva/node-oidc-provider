import { expect } from 'chai';

import bootstrap from '../test_helper.js';

const route = '/jwks';

describe(route, () => {
  describe('with encryption enabled', () => {
    before(bootstrap(import.meta.url, { config: 'jwks-enc' }));

    describe('when populated with signing keys', () => {
      it('responds with json 200', function () {
        return this.agent.get(route)
          .expect('Content-Type', 'application/jwk-set+json; charset=utf-8')
          .expect(200)
          .expect((res) => {
            expect(res.body).to.deep.equal({
              keys: [
                {
                  e: 'AQAB',
                  n: '2s3t1LBJxVpq0aD7GhZYUANkcIzmT6CFAEYe87xpyBUNiGMsLAmoNcyOSs5z3YYdkWCWuFETyr2n7hWN2tYNDR0TegYLdo_tUgvJlXYZRnFf7Jle8FLv2n9BGmFobrVRXoa5EjlccgbnwtibnN0XYDoTgSsoODsMsAsntnPTSQJ2XPmBNg8YlS-EAze7-3IZ_kYGa62bzdOCnTY3M8_HYvDGTLJeUrZfxasncQDVmbCxTWs8H6wKVx6OxwJmyDLFipzTtk9kPh6W37m0StKQcLDTzq3RYD9-o7Rj7qL6KXy6B_hbHP9aKK3Bd46-iYhfTP3ddU-wHJPWGGswr_PAow',
                  kty: 'RSA',
                  kid: 'cMzrEnOQwQCZ2wE0PdUYQN3H_ez6UiobsuNpkHp_UUo',
                },
                {
                  e: 'AQAB',
                  n: 'pyugU-aphpnvdsQwYJptGICF2uXUdKCOBay8PrXbcOOBkaohQfKS8iYSUZYqULCjB8R7uXBc_XrQ17pgDLDDTTdReRpbuxZ_-tfZFh4-gM2vF175IMF8S4ZfIVPeVZWIVBtRPHp5kt9pl_xMqCjNmzwgHoUiJ-iVJ9mQmXq8h_NBEGMuJ3YmcdiE_8uaA9bX_Hi0w73B0S8aB8EFXZ-Z1Ln15qBcpHAvxNT1_bYjL4P14Vs6xcDfYBNDm05lrZJmng_bsqJh6DOYFiqgAVaqA1De-mMaYxiEmZ1M8Tfa9idoKQJK40k8X2yWIeGIEfGurRiHQlRafXPTWTSx-zLaMw',
                  kty: 'RSA',
                  kid: 'inKps3BjRIjEs3kfNnExJjgq4wRn_h_Znaw0xxYEhDM',
                  alg: 'RS256',
                  use: 'sig',
                },
                {
                  e: 'AQAB',
                  n: '-WKKrkieWMKX_SluQKq4i9CyEWAFzTxgpoxkb2_4qp1FLi2HjJVQpchAt4A1M8sPiLo2jM0qebslViFqOPgx5OzJEUQ7cegNb2v6pH47BhcucUHfZr85upxD_mvK4rjpn2D7r_mfZP62clYotvJsKco5rgrN1rpIPuUSxw0HJcyJLiLAeCtPOsJx81y3ekE46vuYqYMmdN12AnGJhW0SELxm02XwlAUcx6nrkGvP4RJf-B1VbBtR2wUCQHbtc9aZ6n8qZ2AMQ7Q_61PZVINit-i64u6vnvzTosKNJsvwR_JytgYOnqCxUyhdqjfYnO0neNttNpsdjLAhfdXEMqCJBw',
                  kty: 'RSA',
                  kid: '1xROmZz_61I8l-LJro_5Zi85OAV_SkI_XYB0ivyVPU0',
                  alg: 'RSA-OAEP',
                  use: 'enc',
                },
                {
                  crv: 'secp256k1',
                  x: 'ADwk2-e--j0e-BPXlgJ_d7funjsWA8fi98u2uVYQUaU',
                  y: 'J9wWPI_2hUxe3PkygNSaiLoUlM2sBPYVREb7EvrXjq0',
                  kty: 'EC',
                  use: 'sig',
                  alg: 'ES256K',
                  kid: 'uNozOx5Tg2nsSkAWGLgOC4XbJj4pf2NFZR01Pc9Xb60',
                },
                {
                  crv: 'P-256',
                  x: '0pm-JC6KeQqFwxdTLsBdtnrT4hV6VDlv3AWE6BSyFSk',
                  y: 'ZvRmSa23_647WNcK_gkp5r8Jm4_9MnuyClguRYvu7Ik',
                  kty: 'EC',
                  kid: 'e0E9_EexvEyoDYUwFH_mbP9FitPWB7JR5fYBIvzVbHA',
                },
                {
                  crv: 'P-256',
                  x: 'LBmYqXV6GXP3-KH26M4FARYEgaTs2_w0CB6p42oVi2g',
                  y: '4b6YSQx6deoyOkPELa_R9vfIm0wEEqrCOHQ_7OCkOEw',
                  kty: 'EC',
                  kid: '7k9sks5sZ3NqrS55feHFQdMBkeG7lCPZGF852ZRkmL0',
                  alg: 'ECDH-ES',
                  use: 'enc',
                },
                {
                  crv: 'Ed448',
                  x: 'bSI-zbfp5DeKlG1-tyQi4_2OZIQdoQYv79BKtotgOkCUYLyuvVQfasiEbpv1RzMPbYLu6Qrxf7QA',
                  kty: 'OKP',
                  kid: 'earwWGhKnBHKVMXdJICpeZxBceKOgDkOzgkM14pm3vQ',
                  use: 'sig',
                  alg: 'EdDSA',
                },
                {
                  crv: 'X448',
                  x: 'VGcaaNI0fHoa0A39PptMppoJU37-WRSh-p4qjPVpORvV-USWGKMAENK22n_HD3zbqsFp9biK7ws',
                  kty: 'OKP',
                  kid: 'jHmhuCbd6IC-O2kf3wsyJqQwkRmkUagoRhqF1OlFwI0',
                  use: 'enc',
                },
              ],
            });
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

  describe('with encryption disabled', () => {
    before(bootstrap(import.meta.url, { config: 'jwks-noenc' }));

    describe('when populated with signing keys', () => {
      it('responds with json 200', function () {
        return this.agent.get(route)
          .expect('Content-Type', 'application/jwk-set+json; charset=utf-8')
          .expect(200)
          .expect((res) => {
            expect(res.body).to.deep.equal({
              keys: [
                {
                  e: 'AQAB',
                  n: '2s3t1LBJxVpq0aD7GhZYUANkcIzmT6CFAEYe87xpyBUNiGMsLAmoNcyOSs5z3YYdkWCWuFETyr2n7hWN2tYNDR0TegYLdo_tUgvJlXYZRnFf7Jle8FLv2n9BGmFobrVRXoa5EjlccgbnwtibnN0XYDoTgSsoODsMsAsntnPTSQJ2XPmBNg8YlS-EAze7-3IZ_kYGa62bzdOCnTY3M8_HYvDGTLJeUrZfxasncQDVmbCxTWs8H6wKVx6OxwJmyDLFipzTtk9kPh6W37m0StKQcLDTzq3RYD9-o7Rj7qL6KXy6B_hbHP9aKK3Bd46-iYhfTP3ddU-wHJPWGGswr_PAow',
                  kty: 'RSA',
                  kid: 'cMzrEnOQwQCZ2wE0PdUYQN3H_ez6UiobsuNpkHp_UUo',
                  use: 'sig',
                },
                {
                  e: 'AQAB',
                  n: 'pyugU-aphpnvdsQwYJptGICF2uXUdKCOBay8PrXbcOOBkaohQfKS8iYSUZYqULCjB8R7uXBc_XrQ17pgDLDDTTdReRpbuxZ_-tfZFh4-gM2vF175IMF8S4ZfIVPeVZWIVBtRPHp5kt9pl_xMqCjNmzwgHoUiJ-iVJ9mQmXq8h_NBEGMuJ3YmcdiE_8uaA9bX_Hi0w73B0S8aB8EFXZ-Z1Ln15qBcpHAvxNT1_bYjL4P14Vs6xcDfYBNDm05lrZJmng_bsqJh6DOYFiqgAVaqA1De-mMaYxiEmZ1M8Tfa9idoKQJK40k8X2yWIeGIEfGurRiHQlRafXPTWTSx-zLaMw',
                  kty: 'RSA',
                  kid: 'inKps3BjRIjEs3kfNnExJjgq4wRn_h_Znaw0xxYEhDM',
                  alg: 'RS256',
                  use: 'sig',
                },
                {
                  crv: 'secp256k1',
                  x: 'ADwk2-e--j0e-BPXlgJ_d7funjsWA8fi98u2uVYQUaU',
                  y: 'J9wWPI_2hUxe3PkygNSaiLoUlM2sBPYVREb7EvrXjq0',
                  kty: 'EC',
                  use: 'sig',
                  alg: 'ES256K',
                  kid: 'uNozOx5Tg2nsSkAWGLgOC4XbJj4pf2NFZR01Pc9Xb60',
                },
                {
                  crv: 'P-256',
                  x: '0pm-JC6KeQqFwxdTLsBdtnrT4hV6VDlv3AWE6BSyFSk',
                  y: 'ZvRmSa23_647WNcK_gkp5r8Jm4_9MnuyClguRYvu7Ik',
                  kty: 'EC',
                  kid: 'e0E9_EexvEyoDYUwFH_mbP9FitPWB7JR5fYBIvzVbHA',
                  use: 'sig',
                  alg: 'ES256',
                },
                {
                  crv: 'Ed448',
                  x: 'bSI-zbfp5DeKlG1-tyQi4_2OZIQdoQYv79BKtotgOkCUYLyuvVQfasiEbpv1RzMPbYLu6Qrxf7QA',
                  kty: 'OKP',
                  kid: 'earwWGhKnBHKVMXdJICpeZxBceKOgDkOzgkM14pm3vQ',
                  use: 'sig',
                  alg: 'EdDSA',
                },
              ],
            });
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
});
