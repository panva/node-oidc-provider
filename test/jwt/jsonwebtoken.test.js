import { expect } from 'chai';
import { generateKeyPair, generateSecret, exportJWK } from 'jose';

import * as JWT from '../../lib/helpers/jwt.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import KeyStore from '../../lib/helpers/keystore.js';

describe('JSON Web Token (JWT) RFC7519 implementation', () => {
  describe('.decode()', () => {
    it('doesnt decode non strings or non buffers', () => {
      expect(() => JWT.decode({})).to.throw(TypeError);
    });

    it('only handles length 3', () => {
      expect(() => JWT.decode('foo.bar.baz.')).to.throw(TypeError);
    });
  });

  it('does not verify none', () => JWT.sign({ data: true }, null, 'none')
    .then((jwt) => JWT.verify(jwt))
    .then((valid) => {
      expect(valid).not.to.be.ok;
    }, (err) => {
      expect(err).to.be.ok;
    }));

  it('does not verify none with a key', async () => {
    const keyobject = await generateSecret('HS256');
    const jwk = await exportJWK(keyobject);

    return JWT.sign({ data: true }, null, 'none')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
      });
  });

  it('signs and validates with oct', async () => {
    const keyobject = await generateSecret('HS256');
    const jwk = await exportJWK(keyobject);
    return JWT.sign({ data: true }, keyobject, 'HS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).not.to.have.property('kid');
        expect(decoded.header).to.have.property('alg', 'HS256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  it('handles utf8 characters', async () => {
    const keyobject = await generateSecret('HS256');
    return JWT.sign({ 'ś∂źć√': 'ś∂źć√' }, keyobject, 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.contain({ 'ś∂źć√': 'ś∂źć√' });
      });
  });

  it('signs and validates with RSA', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'RS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'RS256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  it('signs and validates with EC', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'ES256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'ES256');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  it('signs and validates with EdDSA', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'EdDSA')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'EdDSA');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  describe('sign options', () => {
    it('iat by default', async () => JWT.sign({ data: true }, await generateSecret('HS256'), 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iat');
      }));

    it('expiresIn', async () => JWT.sign({ data: true }, await generateSecret('HS256'), 'HS256', { expiresIn: 60 })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('exp', decoded.payload.iat + 60);
      }));

    it('audience', async () => JWT.sign({ data: true }, await generateSecret('HS256'), 'HS256', { audience: 'clientId' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('aud', 'clientId');
      }));

    it('issuer', async () => JWT.sign({ data: true }, await generateSecret('HS256'), 'HS256', { issuer: 'http://example.com/issuer' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iss', 'http://example.com/issuer');
      }));

    it('subject', async () => JWT.sign({ data: true }, await generateSecret('HS256'), 'HS256', { subject: 'http://example.com/subject' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('sub', 'http://example.com/subject');
      }));
  });

  describe('verify', () => {
    it('nbf', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'jwt not active yet');
        });
    });

    it('nbf ignored', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreNotBefore: true,
        }));
    });

    it('nbf accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('nbf invalid', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: 'not a nbf' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid nbf value');
        });
    });

    it('iat', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'jwt issued in the future');
        });
    });

    it('iat ignored', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreIssued: true,
        }));
    });

    it('iat accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 5 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('iat invalid', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: 'not an iat' }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid iat value');
        });
    });

    it('exp', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'jwt expired');
        });
    });

    it('exp ignored', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreExpiration: true,
        }));
    });

    it('exp accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('exp invalid', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: 'not an exp' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          expect(valid).not.to.be.ok;
        }, (err) => {
          expect(err).to.be.ok;
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'invalid exp value');
        });
    });

    it('audience (single)', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (multi)', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
        authorizedParty: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (single) failed', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
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
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'jwt audience missing pappa');
        });
    });

    it('audience (multi) failed', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
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
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message', 'jwt audience missing pappa');
        });
    });

    it('issuer', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'me',
        }));
    });

    it('issuer failed', async () => {
      const keyobject = await generateSecret('HS256');
      const jwk = await exportJWK(keyobject);
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
          expect(err).to.be.an.instanceOf(Error);
          expect(err).to.have.property('message').that.matches(/jwt issuer invalid/);
        });
    });
  });
});
