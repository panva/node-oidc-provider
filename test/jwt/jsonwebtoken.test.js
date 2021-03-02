const { AssertionError } = require('assert');

const { expect } = require('chai');
const jose = require('jose2');

const JWT = require('../../lib/helpers/jwt');
const epochTime = require('../../lib/helpers/epoch_time');
const KeyStore = require('../../lib/helpers/keystore');

const ks = new jose.JWKS.KeyStore();

describe('JSON Web Token (JWT) RFC7519 implementation', () => {
  before(() => ks.generate('oct', 256)
    .then(() => ks.add(global.keystore.get({ kty: 'RSA' })))
    .then(() => ks.add(global.keystore.get({ kty: 'EC' }))));

  describe('.decode()', () => {
    it('doesnt decode non strings or non buffers', () => {
      expect(() => JWT.decode({})).to.throw(TypeError);
    });

    it('only handles length 3', () => {
      expect(() => JWT.decode('foo.bar.baz.')).to.throw(TypeError);
    });
  });

  it('signs and decodes with none', () => JWT.sign({ data: true }, null, 'none')
    .then((jwt) => JWT.decode(jwt))
    .then((decoded) => {
      expect(decoded.header).not.to.have.property('kid');
      expect(decoded.header).to.have.property('alg', 'none');
      expect(decoded.payload).to.contain({ data: true });
    }));

  it('does not verify none', () => JWT.sign({ data: true }, null, 'none')
    .then((jwt) => JWT.verify(jwt))
    .then((valid) => {
      expect(valid).not.to.be.ok;
    }, (err) => {
      expect(err).to.be.ok;
    }));

  it('does not verify none with a key', () => JWT.sign({ data: true }, null, 'none')
    .then((jwt) => JWT.verify(jwt, new KeyStore([ks.get({ kty: 'oct' }).toJWK(true)])))
    .then((valid) => {
      expect(valid).not.to.be.ok;
    }, (err) => {
      expect(err).to.be.ok;
    }));

  it('signs and validates with oct', () => {
    const key = ks.get({ kty: 'oct' });
    const keyobject = key.keyObject;
    const jwk = key.toJWK(true);
    delete jwk.kid;
    return JWT.sign({ data: true }, keyobject, 'HS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).not.to.have.property('kid');
        expect(decoded.header).to.have.property('alg', 'HS256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  it('handles utf8 characters', () => {
    const key = ks.get({ kty: 'oct' });
    const keyobject = key.keyObject;

    return JWT.sign({ 'ś∂źć√': 'ś∂źć√' }, keyobject, 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.contain({ 'ś∂źć√': 'ś∂źć√' });
      });
  });

  it('signs and validates with RSA', () => {
    const key = ks.get({ kty: 'RSA' });
    const keyobject = key.keyObject;
    const jwk = key.toJWK(false);
    return JWT.sign({ data: true }, keyobject, 'RS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'RS256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  it('signs and validates with EC', () => {
    const key = ks.get({ kty: 'EC' });
    const keyobject = key.keyObject;
    const jwk = key.toJWK(false);
    return JWT.sign({ data: true }, keyobject, 'ES256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'ES256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  describe('sign options', () => {
    it('iat by default', () => JWT.sign({ data: true }, null, 'none')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iat');
      }));

    it('expiresIn', () => JWT.sign({ data: true }, null, 'none', { expiresIn: 60 })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('exp', decoded.payload.iat + 60);
      }));

    it('audience', () => JWT.sign({ data: true }, null, 'none', { audience: 'clientId' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('aud', 'clientId');
      }));

    it('issuer', () => JWT.sign({ data: true }, null, 'none', { issuer: 'http://example.com/issuer' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iss', 'http://example.com/issuer');
      }));

    it('subject', () => JWT.sign({ data: true }, null, 'none', { subject: 'http://example.com/subject' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('sub', 'http://example.com/subject');
      }));
  });

  describe('verify', () => {
    it('nbf', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'jwt not active yet');
        });
    });

    it('nbf ignored', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreNotBefore: true,
        }));
    });

    it('nbf accepted within set clock tolerance', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, nbf: epochTime() + 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('nbf invalid', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, nbf: 'not a nbf' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'invalid nbf value');
        });
    });

    it('iat', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'jwt issued in the future');
        });
    });

    it('iat ignored', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreIssued: true,
        }));
    });

    it('iat accepted within set clock tolerance', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, iat: epochTime() + 5 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('iat invalid', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, iat: 'not an iat' }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'invalid iat value');
        });
    });

    it('exp', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'jwt expired');
        });
    });

    it('exp ignored', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreExpiration: true,
        }));
    });

    it('exp accepted within set clock tolerance', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, exp: epochTime() - 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('exp invalid', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true, exp: 'not an exp' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'invalid exp value');
        });
    });

    it('audience (single)', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (multi)', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
        authorizedParty: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (single) failed', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'pappa',
        }))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        })
        .catch((err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'jwt audience missing pappa');
        });
    });

    it('audience (multi) failed', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'pappa',
        }))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        })
        .catch((err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message', 'jwt audience missing pappa');
        });
    });

    it('issuer', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'me',
        }));
    });

    it('issuer failed', () => {
      const key = ks.get({ kty: 'oct' });
      const keyobject = key.keyObject;
      const jwk = key.toJWK(true);
      delete jwk.kid;
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'you',
        }))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        })
        .catch((err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(AssertionError);
          expect(err).to.have.property('message').that.matches(/jwt issuer invalid/);
        });
    });
  });
});
