import { rejects } from 'node:assert/strict';

import { expect } from 'chai';
import { generateKeyPair, generateSecret, exportJWK } from 'jose';

import * as JWT from '../../lib/helpers/jwt.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import KeyStore from '../../lib/helpers/keystore.js';

function countKeyObjectCalls(keystore) {
  const getKeyObject = keystore.getKeyObject.bind(keystore);
  let calls = 0;
  keystore.getKeyObject = (...args) => {
    calls += 1;
    return getKeyObject(...args);
  };
  return () => calls;
}

describe('JSON Web Token (JWT) RFC7519 implementation', () => {
  it('reports unsupported algorithms', () => {
    const keystore = new KeyStore();

    expect(() => keystore.selectForVerify({ alg: 'unsupported' }))
      .to.throw('unsupported JWS algorithm (unsupported)');
    expect(() => keystore.selectForDecrypt({ alg: 'unsupported' }))
      .to.throw('unsupported JWE key management algorithm (unsupported)');
  });

  describe('.decode()', () => {
    it('doesnt decode non strings or non buffers', () => {
      expect(() => JWT.decode({})).to.throw(TypeError);
    });

    it('only handles length 3', () => {
      expect(() => JWT.decode('foo.bar.baz.')).to.throw(TypeError);
    });

    it('only handles JSON object headers and payloads', () => {
      const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

      expect(() => JWT.decode(`${encode(null)}.${encode({})}.signature`)).to.throw();
      expect(() => JWT.decode(`${encode({})}.${encode(null)}.signature`)).to.throw();
      expect(() => JWT.decode(`${encode({})}.${encode([])}.signature`)).to.throw();
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
    const keyobject = await generateSecret('HS256', { extractable: true });
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
    const keyobject = await generateSecret('HS256', { extractable: true });
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
    const keyobject = await generateSecret('HS256', { extractable: true });
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

  it('signs and validates with Ed25519', async () => {
    const { privateKey, publicKey } = await generateKeyPair('Ed25519');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'Ed25519')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        expect(decoded.header).to.have.property('alg', 'Ed25519');
        expect(decoded.payload).to.contain({ data: true });
      });
  });

  describe('candidate keys', () => {
    let signingKeys;
    let signingJwks;
    let encryptionKeys;
    let encryptionJwks;

    before(async () => {
      signingKeys = await Promise.all(Array.from(
        { length: 4 },
        () => generateSecret('HS256', { extractable: true }),
      ));
      signingJwks = await Promise.all(signingKeys.map((key) => exportJWK(key)));
      encryptionKeys = await Promise.all(Array.from(
        { length: 4 },
        () => generateSecret('A128GCM', { extractable: true }),
      ));
      encryptionJwks = await Promise.all(encryptionKeys.map((key) => exportJWK(key)));
    });

    for (const [label, position] of [['first', 0], ['middle', 1], ['last', 2]]) {
      it(`stops verification after the ${label} successful key`, async () => {
        const jwt = await JWT.sign({ data: true }, signingKeys[position], 'HS256');
        const keystore = new KeyStore(signingJwks.slice(0, 3));
        const calls = countKeyObjectCalls(keystore);

        await JWT.verify(jwt, keystore);

        expect(calls()).to.equal(position + 1);
      });

      it(`stops decryption after the ${label} successful key`, async () => {
        const jwe = await JWT.encrypt('cleartext', encryptionKeys[position], {
          alg: 'dir', enc: 'A128GCM',
        });
        const keystore = new KeyStore(encryptionJwks.slice(0, 3));
        const calls = countKeyObjectCalls(keystore);

        expect(await JWT.decrypt(jwe, keystore)).to.deep.equal(Buffer.from('cleartext'));
        expect(calls()).to.equal(position + 1);
      });
    }

    it('tries every verification key when none succeeds', async () => {
      const jwt = await JWT.sign({ data: true }, signingKeys[3], 'HS256');
      const keystore = new KeyStore(signingJwks.slice(0, 3));
      const calls = countKeyObjectCalls(keystore);

      await rejects(JWT.verify(jwt, keystore));
      expect(calls()).to.equal(3);
    });

    it('tries every decryption key when none succeeds', async () => {
      const jwe = await JWT.encrypt('cleartext', encryptionKeys[3], {
        alg: 'dir', enc: 'A128GCM',
      });
      const keystore = new KeyStore(encryptionJwks.slice(0, 3));
      const calls = countKeyObjectCalls(keystore);

      await rejects(JWT.decrypt(jwe, keystore));
      expect(calls()).to.equal(3);
    });

    it('refreshes a stale keystore after every candidate fails', async () => {
      const jwt = await JWT.sign({ data: true }, signingKeys[3], 'HS256');
      const keystore = new KeyStore(signingJwks.slice(0, 3));
      let stale = true;
      let refreshes = 0;
      keystore.fresh = () => !stale;
      keystore.refresh = async () => {
        stale = false;
        refreshes += 1;
        keystore.clear();
        keystore.add(signingJwks[3]);
      };

      expect((await JWT.verify(jwt, keystore)).payload).to.have.property('data', true);
      expect(refreshes).to.equal(1);
    });
  });

  describe('sign options', () => {
    it('iat by default', async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iat');
      }));

    it('expiresIn', async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { expiresIn: 60 })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('exp', decoded.payload.iat + 60);
      }));

    it('audience', async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { audience: 'clientId' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('aud', 'clientId');
      }));

    it('issuer', async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { issuer: 'http://example.com/issuer' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iss', 'http://example.com/issuer');
      }));

    it('subject', async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { subject: 'http://example.com/subject' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('sub', 'http://example.com/subject');
      }));
  });

  describe('verify', () => {
    it('nbf', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreNotBefore: true,
        }));
    });

    it('nbf accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('nbf invalid', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreIssued: true,
        }));
    });

    it('iat accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 5 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('iat invalid', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreExpiration: true,
        }));
    });

    it('exp accepted within set clock tolerance', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('exp invalid', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (multi)', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (single) failed', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
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
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'me',
        }));
    });

    it('issuer failed', async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
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
