const { parse } = require('url');

const jose = require('jose');
const sinon = require('sinon');
const { expect } = require('chai');

const { Provider } = require('../../lib');
const JWT = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');

describe('request parameter features', () => {
  before(bootstrap(__dirname));

  describe('merging strategies', () => {
    ['lax', 'strict', 'whitelist'].forEach((value) => {
      it(`${value} is an allowed strategy name`, () => {
        expect(() => {
          new Provider('http://localhost:3000', { // eslint-disable-line no-new
            features: {
              requestObjects: {
                mergingStrategy: {
                  name: value,
                },
              },
            },
          });
        }).not.to.throw();
      });
    });

    it('throws on unsupported strategy names', () => {
      expect(() => {
        new Provider('http://localhost:3000', { // eslint-disable-line no-new
          features: {
            requestObjects: {
              mergingStrategy: {
                name: 'foobar',
              },
            },
          },
        });
      }).to.throw(TypeError, "'mergingStrategy.name' must be 'lax', 'strict', or 'whitelist'");
    });
  });

  describe('configuration features.requestUri', () => {
    it('extends discovery', async function () {
      await this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_parameter_supported', true);
          expect(response.body).not.to.have.property('require_signed_request_object');
        });

      i(this.provider).configuration('features.requestObjects').requireSignedRequestObject = true;

      await this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_parameter_supported', true);
          expect(response.body).to.have.property('require_signed_request_object', true);
        });
    });

    after(function () {
      i(this.provider).configuration('features.requestObjects').requireSignedRequestObject = false;
    });
  });

  function redirectSuccess(response) {
    const expected = parse('https://client.example.com/cb', true);
    const actual = parse(response.headers.location, true);
    ['protocol', 'host', 'pathname'].forEach((attr) => {
      expect(actual[attr]).to.equal(expected[attr]);
    });
    expect(actual.query).to.have.property('code');
  }
  function httpSuccess({ body }) {
    expect(body).to.contain.key('device_code');
  }

  [
    ['/auth', 'get', 'authorization.error', 302, 302, redirectSuccess, 'authorization.success'],
    ['/auth', 'post', 'authorization.error', 302, 302, redirectSuccess, 'authorization.success'],
    ['/device/auth', 'post', 'device_authorization.error', 200, 400, httpSuccess, 'device_authorization.success'],
  ].forEach(([
    route, verb, errorEvt, successCode, errorCode, successFnCheck, successEvt,
  ], index) => {
    describe(`${route} ${verb} passing request parameters as JWTs`, () => {
      before(function () {
        return this.login({
          claims: { id_token: { email: null } },
        });
      });
      after(function () {
        i(this.provider).configuration().clockTolerance = 0;
        return this.logout();
      });

      describe('merging strategies', () => {
        beforeEach(function () {
          const ro = i(this.provider).configuration().features.requestObjects;
          this.orig = {
            mergingStrategy: ro.mergingStrategy.name,
            whitelist: [...ro.mergingStrategy.whitelist],
          };
        });

        afterEach(function () {
          const ro = i(this.provider).configuration().features.requestObjects;
          ro.mergingStrategy.name = this.orig.mergingStrategy;
          ro.mergingStrategy.whitelist = new Set(this.orig.whitelist);
        });

        describe('strict', () => {
          it('does not use anything from the OAuth 2.0 parameters', async function () {
            i(this.provider).configuration().features.requestObjects.mergingStrategy.name = 'strict';

            const spy = sinon.spy();
            this.provider.once('authorization.success', spy);

            if (successCode === 200) {
              this.provider.once('device_authorization.success', ({ oidc }) => {
                this.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
              });
            }

            await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
              agent: this.agent,
              route,
              verb,
              auth: {
                request,
                ui_locales: 'foo',
                ...(successCode === 200 ? {
                  client_id: 'client',
                } : undefined),
              },
            })
              .expect(successCode)
              .expect(successFnCheck)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(spy.args[0][0].oidc.params.ui_locales).to.eq(undefined);
              }));
          });
        });

        describe('lax', () => {
          it('uses anything not found in the Request Object', async function () {
            i(this.provider).configuration().features.requestObjects.mergingStrategy.name = 'lax';

            const spy = sinon.spy();
            this.provider.once('authorization.success', spy);

            if (successCode === 200) {
              this.provider.once('device_authorization.success', ({ oidc }) => {
                this.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
              });
            }

            await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
              agent: this.agent,
              route,
              verb,
              auth: {
                request,
                ui_locales: 'foo',
                ...(successCode === 200 ? {
                  client_id: 'client',
                } : undefined),
              },
            })
              .expect(successCode)
              .expect(successFnCheck)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(spy.args[0][0].oidc.params.ui_locales).to.eq('foo');
              }));
          });
        });

        describe('whitelist', () => {
          it('uses anything not found in the Request Object', async function () {
            i(this.provider).configuration()
              .features.requestObjects.mergingStrategy.name = 'whitelist';
            i(this.provider).configuration()
              .features.requestObjects.mergingStrategy.whitelist = new Set([
                'ui_locales',
              ]);

            const spy = sinon.spy();
            this.provider.once('authorization.success', spy);

            if (successCode === 200) {
              this.provider.once('device_authorization.success', ({ oidc }) => {
                this.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
              });
            }

            await JWT.sign({
              client_id: 'client',
              response_type: 'code',
              redirect_uri: 'https://client.example.com/cb',
              scope: 'openid',
            }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
              agent: this.agent,
              route,
              verb,
              auth: {
                request,
                ui_locales: 'foo',
                claims_locales: 'foo',
                ...(successCode === 200 ? {
                  client_id: 'client',
                } : undefined),
              },
            })
              .expect(successCode)
              .expect(successFnCheck)
              .expect(() => {
                expect(spy.calledOnce).to.be.true;
                expect(spy.args[0][0].oidc.params.ui_locales).to.eq('foo');
                expect(spy.args[0][0].oidc.params.claims_locales).to.eq(undefined);
              }));
          });
        });
      });

      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });

      it('works with signed by none unless the client is required to use SIGNED request object', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client-requiredSignedRequestObject',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client-requiredSignedRequestObject', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-requiredSignedRequestObject',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must not be unsigned for this client',
            );
          }));
      });

      describe('JAR only request', () => {
        it('works without any other params', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              ...(successCode === 200 ? {
                client_id: 'client',
              } : undefined),
            },
          })
            .expect(successCode)
            .expect(successFnCheck));
        });

        it('when invalid Request Object', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request: 'foo',
              ...(successCode === 200 ? {
                client_id: 'client',
              } : undefined),
            },
          })
            .expect(400)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                route !== '/device/auth' ? 'Request Object is not a valid JWT' : 'could not parse Request Object (invalid JWT.decode input)',
              );
            });
        });

        it('if without client_id', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            // client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, null, 'none', { /* issuer: 'client', */ audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
            },
          })
            .expect(400)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                route !== '/device/auth' ? "missing required parameter 'client_id'" : 'no client authentication mechanism provided',
              );
            }));
        });

        it('if with empty client_id', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: '',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, null, 'none', { issuer: '', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
            },
          })
            .expect(400)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                route !== '/device/auth' ? "missing required parameter 'client_id'" : 'no client authentication mechanism provided',
              );
            }));
        });

        it('if with invalid type client_id', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: 123678,
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            scope: 'openid',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
            },
          })
            .expect(400)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                route !== '/device/auth' ? "missing required parameter 'client_id'" : 'no client authentication mechanism provided',
              );
            }));
        });
      });

      it('fails to process a request without request', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must be used by this client',
            );
          });
      });

      it('can contain max_age parameter as a number and it (and other params too) will be forced as string', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          max_age: 300,
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        expect(
          spy.calledWithMatch({ oidc: { params: { max_age: sinon.match.string } } }),
        ).to.be.true;
      });

      it('can contain claims parameter as JSON', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);
        const claims = JSON.stringify({ id_token: { email: null } });

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          claims,
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        expect(
          spy.calledWithMatch({ oidc: { params: { claims } } }),
        ).to.be.true;
      });

      it('can contain claims parameter as object', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);
        const claims = { id_token: { email: null } };

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          claims: { id_token: { email: null } },
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        expect(
          spy.calledWithMatch({ oidc: { params: { claims: JSON.stringify(claims) } } }),
        ).to.be.true;
      });

      it('can accept Request Objects issued within acceptable system clock skew', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        i(this.provider).configuration().clockTolerance = 10;
        return JWT.sign({
          iat: Math.ceil(Date.now() / 1000) + 5,
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });

      it('works with signed by an actual DSA', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });

      it('rejects HMAC based requests when signed with an expired secret', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig-expired')).keystore.get({
          alg: 'HS256',
        });

        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client-with-HS-sig-expired',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig-expired', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig-expired',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'could not validate the Request Object - the client secret used for its signature is expired',
            );
          }));
      });

      it('supports optional replay prevention', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });

        const request = await JWT.sign({
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          jti: `very-random-and-collision-resistant-${index}`,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer, expiresIn: 30 });

        await this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck);

        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        await this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description').that.matches(/request replay detected/);
          });
      });

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must not contain request or request_uri properties',
            );
          }));
      });

      it('doesnt allow requestUri inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must not contain request or request_uri properties',
            );
          }));
      });

      it('can contain resource parameter as an Array', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          resource: ['https://rp.example.com/api'],
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        expect(
          spy.calledWithMatch({ oidc: { params: { resource: ['https://rp.example.com/api'] } } }),
        ).to.be.true;
      });

      if (route !== '/device/auth') {
        it('may contain a response_mode and it will be honoured', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            response_mode: 'fragment',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(this.AuthorizationRequest.prototype.validateFragment)
            .expect(successCode)
            .expect(successFnCheck));
        });

        it('re-checks the response mode from the request', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: 'client2',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            response_mode: 'foo',
          }, null, 'none', { issuer: 'client2', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'unsupported_response_mode');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'unsupported response_mode requested',
              );
            }));
        });

        it('doesnt allow response_type to differ', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: 'client',
            response_type: 'id_token',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'request response_type must equal the one in request parameters',
              );
            }));
        });

        it('uses the state from the request even if its validations will fail', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: 'client2',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            state: 'foobar',
          }, null, 'none', { issuer: 'client2', audience: this.provider.issuer }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(this.AuthorizationRequest.prototype.validateResponseParameter.call({}, 'state', 'foobar'))
            .expect(errorCode)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'request client_id must equal the one in request parameters',
              );
            }));
        });
      }

      it('handles JWT claim assertions', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          exp: 1,
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object claims are invalid (jwt expired)',
            );
          }));
      });

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client2', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'request client_id must equal the one in request parameters',
            );
          }));
      });

      it('handles invalid signed looklike jwts', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request: 'definitely.notsigned.jwt',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description').and.matches(/could not parse Request Object/);
          });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'the preregistered alg must be used in request or request_uri',
            );
          }));
      });

      it('unsupported algs must not be used', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);
        const secret = (await this.provider.Client.find('client')).clientSecret;
        const key = jose.JWK.asKey(secret);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS384', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description', 'unsupported signed request alg');
          }));
      });

      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description').that.matches(/could not validate Request Object/);
          }));
      });

      it('rejects "registration" parameter part of the Request Object', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          registration: 'foo',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'registration_not_supported');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'registration parameter provided but not supported',
            );
          }));
      });

      it('handles unrecognized parameters', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          unrecognized: true,
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });
    });
  });
});
