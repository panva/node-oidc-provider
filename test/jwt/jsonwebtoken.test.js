'use strict';

const JWT = require('../../lib/helpers/jwt');
const { expect } = require('chai');
const jose = require('node-jose');
const epochTime = require('../../lib/helpers/epoch_time');

const keystore = jose.JWK.createKeyStore();

describe('JSON Web Token (JWT) RFC7519 implementation', function () {
  before(function () {
    return keystore.generate('oct', 256)
      .then(keystore.generate('RSA', 512))
      .then(keystore.generate('EC', 'P-256'));
  });

  it('signs and validates with none', function () {
    return JWT.sign({ data: true }, null, 'none', {
      noTimestamp: true
    })
    .then(jwt => JWT.decode(jwt))
    .then((decoded) => {
      expect(decoded.header).not.to.have.property('kid');
      expect(decoded.header).to.have.property('alg', 'none');
      expect(decoded.payload).to.eql({ data: true });
    });
  });

  it('signs and validates with oct', function () {
    const key = keystore.get({ kty: 'oct' });
    return JWT.sign({ data: true }, key, 'HS256', {
      noTimestamp: true
    })
    .then(jwt => JWT.verify(jwt, key))
    .then((decoded) => {
      expect(decoded.header).not.to.have.property('kid');
      expect(decoded.header).to.have.property('alg', 'HS256');
      expect(decoded.payload).to.eql({ data: true });
    });
  });

  it('signs and validates with RSA', function () {
    const key = keystore.get({ kty: 'RSA' });
    return JWT.sign({ data: true }, key, 'RS256', {
      noTimestamp: true
    })
    .then(jwt => JWT.verify(jwt, key))
    .then((decoded) => {
      expect(decoded.header).to.have.property('kid');
      expect(decoded.header).to.have.property('alg', 'RS256');
      expect(decoded.payload).to.eql({ data: true });
    });
  });

  it('signs and validates with EC', function () {
    const key = keystore.get({ kty: 'EC' });
    return JWT.sign({ data: true }, key, 'ES256', {
      noTimestamp: true
    })
    .then(jwt => JWT.verify(jwt, key))
    .then((decoded) => {
      expect(decoded.header).to.have.property('kid');
      expect(decoded.header).to.have.property('alg', 'ES256');
      expect(decoded.payload).to.eql({ data: true });
    });
  });

  describe('sign options', function () {
    it('iat by default', function () {
      return JWT.sign({ data: true }, null, 'none')
      .then(jwt => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iat');
      });
    });

    it('expiresIn', function () {
      return JWT.sign({ data: true }, null, 'none', { expiresIn: 60 })
      .then(jwt => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('exp', decoded.payload.iat + 60);
      });
    });

    it('audience', function () {
      return JWT.sign({ data: true }, null, 'none', { audience: 'clientId' })
      .then(jwt => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('aud', 'clientId');
      });
    });

    it('issuer', function () {
      return JWT.sign({ data: true }, null, 'none', { issuer: 'http://example.com/issuer' })
      .then(jwt => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('iss', 'http://example.com/issuer');
      });
    });

    it('subject', function () {
      return JWT.sign({ data: true }, null, 'none', { subject: 'http://example.com/subject' })
      .then(jwt => JWT.decode(jwt))
      .then((decoded) => {
        expect(decoded.payload).to.have.property('sub', 'http://example.com/subject');
      });
    });
  });

  describe('verify', function () {
    it('nbf', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'jwt not active yet');
      });
    });

    it('nbf ignored', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, nbf: epochTime() + 3600 }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key, {
        ignoreNotBefore: true
      }));
    });

    it('nbf invalid', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, nbf: 'not a nbf' }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'invalid nbf value');
      });
    });

    it('iat', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, key, 'HS256', {
        noTimestamp: true
      })
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'jwt issued in the future');
      });
    });

    it('iat ignored', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, iat: epochTime() + 3600 }, key, 'HS256', {
        noTimestamp: true
      })
      .then(jwt => JWT.verify(jwt, key, {
        ignoreIssued: true
      }));
    });

    it('iat invalid', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, iat: 'not an iat' }, key, 'HS256', {
        noTimestamp: true
      })
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'invalid iat value');
      });
    });

    it('exp', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'jwt expired');
      });
    });

    it('exp ignored', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, exp: epochTime() - 3600 }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key, {
        ignoreExpiration: true
      }));
    });

    it('exp invalid', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true, exp: 'not an exp' }, key, 'HS256')
      .then(jwt => JWT.verify(jwt, key))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      }, (err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message', 'invalid exp value');
      });
    });

    it('audience (single)', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        audience: 'client'
      })
      .then(jwt => JWT.verify(jwt, key, {
        audience: 'client'
      }));
    });

    it('audience (multi)', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        audience: ['client', 'momma']
      })
      .then(jwt => JWT.verify(jwt, key, {
        audience: 'momma'
      }));
    });

    it('audience (single) failed', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        audience: 'client'
      })
      .then(jwt => JWT.verify(jwt, key, {
        audience: ['pappa']
      }))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      })
      .catch((err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message').that.matches(/jwt audience invalid/);
      });
    });

    it('audience (multi) failed', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        audience: ['client', 'momma']
      })
      .then(jwt => JWT.verify(jwt, key, {
        audience: 'pappa'
      }))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      })
      .catch((err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message').that.matches(/jwt audience invalid/);
      });
    });

    it('issuer', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        issuer: 'me'
      })
      .then(jwt => JWT.verify(jwt, key, {
        issuer: 'me'
      }));
    });

    it('issuer failed', function () {
      const key = keystore.get({ kty: 'oct' });
      return JWT.sign({ data: true }, key, 'HS256', {
        issuer: 'me'
      })
      .then(jwt => JWT.verify(jwt, key, {
        issuer: 'you'
      }))
      .then((valid) => {
        expect(valid).not.to.be.ok;
      })
      .catch((err) => {
        expect(err).to.be.ok;
        expect(err).to.have.property('name', 'AssertionError');
        expect(err).to.have.property('message').that.matches(/jwt issuer invalid/);
      });
    });
  });
});
