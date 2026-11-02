import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { rejects } from 'node:assert/strict';

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
  it('reports unsupported algorithms', { timeout: 3000 }, () => {
    const keystore = new KeyStore();

    assert.throws(() => keystore.selectForVerify({ alg: 'unsupported' }), (error) => { assert.ok(error.message.includes('unsupported JWS algorithm (unsupported)')); return true; });
    assert.throws(() => keystore.selectForDecrypt({ alg: 'unsupported' }), (error) => { assert.ok(error.message.includes('unsupported JWE key management algorithm (unsupported)')); return true; });
  });

  describe('.decode()', () => {
    it('doesnt decode non strings or non buffers', { timeout: 3000 }, () => {
      assert.throws(() => JWT.decode({}), (error) => { assert.ok(error instanceof TypeError); return true; });
    });

    it('only handles length 3', { timeout: 3000 }, () => {
      assert.throws(() => JWT.decode('foo.bar.baz.'), (error) => { assert.ok(error instanceof TypeError); return true; });
    });

    it('only handles JSON object headers and payloads', { timeout: 3000 }, () => {
      const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

      assert.throws(() => JWT.decode(`${encode(null)}.${encode({})}.signature`));
      assert.throws(() => JWT.decode(`${encode({})}.${encode(null)}.signature`));
      assert.throws(() => JWT.decode(`${encode({})}.${encode([])}.signature`));
    });
  });

  it('does not verify none', { timeout: 3000 }, () => JWT.sign({ data: true }, null, 'none')
    .then((jwt) => JWT.verify(jwt))
    .then((valid) => {
      assert.ok(!(valid));
    }, (err) => {
      assert.ok(err);
    }));

  it('does not verify none with a key', { timeout: 3000 }, async () => {
    const keyobject = await generateSecret('HS256', { extractable: true });
    const jwk = await exportJWK(keyobject);

    return JWT.sign({ data: true }, null, 'none')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((valid) => {
        assert.ok(!(valid));
      }, (err) => {
        assert.ok(err);
      });
  });

  it('signs and validates with oct', { timeout: 3000 }, async () => {
    const keyobject = await generateSecret('HS256', { extractable: true });
    const jwk = await exportJWK(keyobject);
    return JWT.sign({ data: true }, keyobject, 'HS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        assert.ok(!('kid' in Object(decoded.header)));
        ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'HS256'); })(decoded.header);
        ((actual) => { assert.ok("data" in Object(actual)); assert.equal(actual.data, true); })(decoded.payload);
      });
  });

  it('handles utf8 characters', { timeout: 3000 }, async () => {
    const keyobject = await generateSecret('HS256', { extractable: true });
    return JWT.sign({ 'ś∂źć√': 'ś∂źć√' }, keyobject, 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        ((actual) => { assert.ok("ś∂źć√" in Object(actual)); assert.equal(actual["ś∂źć√"], 'ś∂źć√'); })(decoded.payload);
      });
  });

  it('signs and validates with RSA', { timeout: 3000 }, async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'RS256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'RS256'); })(decoded.header);
        ((actual) => { assert.ok("data" in Object(actual)); assert.equal(actual.data, true); })(decoded.payload);
      });
  });

  it('signs and validates with EC', { timeout: 3000 }, async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'ES256')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'ES256'); })(decoded.header);
        ((actual) => { assert.ok("data" in Object(actual)); assert.equal(actual.data, true); })(decoded.payload);
      });
  });

  it('signs and validates with EdDSA', { timeout: 3000 }, async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'EdDSA')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'EdDSA'); })(decoded.header);
        ((actual) => { assert.ok("data" in Object(actual)); assert.equal(actual.data, true); })(decoded.payload);
      });
  });

  it('signs and validates with Ed25519', { timeout: 3000 }, async () => {
    const { privateKey, publicKey } = await generateKeyPair('Ed25519');
    const jwk = await exportJWK(publicKey);
    return JWT.sign({ data: true }, privateKey, 'Ed25519')
      .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
      .then((decoded) => {
        ((actual) => { assert.ok('alg' in Object(actual)); assert.equal(actual.alg, 'Ed25519'); })(decoded.header);
        ((actual) => { assert.ok("data" in Object(actual)); assert.equal(actual.data, true); })(decoded.payload);
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
    }, { timeout: 3000 });

    for (const [label, position] of [['first', 0], ['middle', 1], ['last', 2]]) {
      it(`stops verification after the ${label} successful key`, { timeout: 3000 }, async () => {
        const jwt = await JWT.sign({ data: true }, signingKeys[position], 'HS256');
        const keystore = new KeyStore(signingJwks.slice(0, 3));
        const calls = countKeyObjectCalls(keystore);

        await JWT.verify(jwt, keystore);

        assert.equal(calls(), position + 1);
      });

      it(`stops decryption after the ${label} successful key`, { timeout: 3000 }, async () => {
        const jwe = await JWT.encrypt('cleartext', encryptionKeys[position], {
          alg: 'dir', enc: 'A128GCM',
        });
        const keystore = new KeyStore(encryptionJwks.slice(0, 3));
        const calls = countKeyObjectCalls(keystore);

        assert.deepEqual(await JWT.decrypt(jwe, keystore), Buffer.from('cleartext'));
        assert.equal(calls(), position + 1);
      });
    }

    it('tries every verification key when none succeeds', { timeout: 3000 }, async () => {
      const jwt = await JWT.sign({ data: true }, signingKeys[3], 'HS256');
      const keystore = new KeyStore(signingJwks.slice(0, 3));
      const calls = countKeyObjectCalls(keystore);

      await rejects(JWT.verify(jwt, keystore));
      assert.equal(calls(), 3);
    });

    it('tries every decryption key when none succeeds', { timeout: 3000 }, async () => {
      const jwe = await JWT.encrypt('cleartext', encryptionKeys[3], {
        alg: 'dir', enc: 'A128GCM',
      });
      const keystore = new KeyStore(encryptionJwks.slice(0, 3));
      const calls = countKeyObjectCalls(keystore);

      await rejects(JWT.decrypt(jwe, keystore));
      assert.equal(calls(), 3);
    });

    it('refreshes a stale keystore after every candidate fails', { timeout: 3000 }, async () => {
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

      ((actual) => { assert.ok('data' in Object(actual)); assert.equal(actual.data, true); })((await JWT.verify(jwt, keystore)).payload);
      assert.equal(refreshes, 1);
    });
  });

  describe('sign options', () => {
    it('iat by default', { timeout: 3000 }, async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256')
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        assert.ok('iat' in Object(decoded.payload));
      }));

    it('expiresIn', { timeout: 3000 }, async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { expiresIn: 60 })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        ((actual) => { assert.ok('exp' in Object(actual)); assert.equal(actual.exp, decoded.payload.iat + 60); })(decoded.payload);
      }));

    it('audience', { timeout: 3000 }, async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { audience: 'clientId' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'clientId'); })(decoded.payload);
      }));

    it('issuer', { timeout: 3000 }, async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { issuer: 'http://example.com/issuer' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, 'http://example.com/issuer'); })(decoded.payload);
      }));

    it('subject', { timeout: 3000 }, async () => JWT.sign({ data: true }, await generateSecret('HS256', { extractable: true }), 'HS256', { subject: 'http://example.com/subject' })
      .then((jwt) => JWT.decode(jwt))
      .then((decoded) => {
        ((actual) => { assert.ok('sub' in Object(actual)); assert.equal(actual.sub, 'http://example.com/subject'); })(decoded.payload);
      }));
  });

  describe('verify', () => {
    it('nbf', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'jwt not active yet'); })(err);
        });
    });

    it('nbf ignored', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreNotBefore: true,
        }));
    });

    it('nbf accepted within set clock tolerance', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: epochTime() + 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('nbf invalid', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, nbf: 'not a nbf' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid nbf value'); })(err);
        });
    });

    it('iat', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'jwt issued in the future'); })(err);
        });
    });

    it('iat ignored', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreIssued: true,
        }));
    });

    it('iat accepted within set clock tolerance', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: epochTime() + 5 }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('iat invalid', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, iat: 'not an iat' }, keyobject, 'HS256', {
        noTimestamp: true,
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid iat value'); })(err);
        });
    });

    it('exp', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'jwt expired'); })(err);
        });
    });

    it('exp ignored', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          ignoreExpiration: true,
        }));
    });

    it('exp accepted within set clock tolerance', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: epochTime() - 5 }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          clockTolerance: 10,
        }));
    });

    it('exp invalid', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true, exp: 'not an exp' }, keyobject, 'HS256')
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
        .then((valid) => {
          assert.ok(!(valid));
        }, (err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid exp value'); })(err);
        });
    });

    it('audience (single)', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (multi)', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'client',
        }));
    });

    it('audience (single) failed', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: 'client',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'pappa',
        }))
        .then((valid) => {
          assert.ok(!(valid));
        })
        .catch((err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'jwt audience missing pappa'); })(err);
        });
    });

    it('audience (multi) failed', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        audience: ['client', 'momma'],
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          audience: 'pappa',
        }))
        .then((valid) => {
          assert.ok(!(valid));
        })
        .catch((err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'jwt audience missing pappa'); })(err);
        });
    });

    it('issuer', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'me',
        }));
    });

    it('issuer failed', { timeout: 3000 }, async () => {
      const keyobject = await generateSecret('HS256', { extractable: true });
      const jwk = await exportJWK(keyobject);
      return JWT.sign({ data: true }, keyobject, 'HS256', {
        issuer: 'me',
      })
        .then((jwt) => JWT.verify(jwt, new KeyStore([jwk]), {
          issuer: 'you',
        }))
        .then((valid) => {
          assert.ok(!(valid));
        })
        .catch((err) => {
          assert.ok(err);
          ((actual) => { assert.ok(actual instanceof Error); })(err);
          ((actual) => { assert.ok('message' in Object(actual)); assert.match(actual.message, /jwt issuer invalid/); })(err);
        });
    });
  });
});
