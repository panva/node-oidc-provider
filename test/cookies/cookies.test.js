const { expect } = require('chai');
const sinon = require('sinon');
const timekeeper = require('timekeeper');

const Cookies = require('../../lib/cookies');

describe('cookies module', () => {
  before(() => {
    timekeeper.freeze(new Date(1569604320000));
  });

  after(() => {
    timekeeper.reset();
  });

  describe('cookies#get', () => {
    it('returns undefined when no cookie header was received', () => {
      const c = new Cookies({ headers: {} });
      expect(c.get('foo')).to.eql(undefined);
    });

    it('returns undefined when the cookie isnt sent', () => {
      const c = new Cookies({
        headers: {
          cookie: 'foo=bar',
        },
      });
      expect(c.get('ba')).to.eql(undefined);
    });

    it('returns an unsigned cookie', () => {
      const c = new Cookies({
        headers: {
          cookie: 'foo=bar',
        },
      });
      expect(c.get('foo')).to.eql('bar');
    });

    it('returns an unsigned cookie without options', () => {
      const c = new Cookies(
        {
          headers: {
            cookie: 'foo=bar',
          },
        },
        {},
        { keys: ['foo', 'bar'] },
      );
      expect(c.get('foo')).to.eql('bar');
    });

    it('returns a unsigned cookie with options.signed = false', () => {
      const c = new Cookies(
        {
          headers: {
            cookie: 'foo=bar',
          },
        },
        {},
      );
      expect(c.get('foo', { signed: false })).to.eql('bar');
    });

    it('returns undefined when .sig cookie is missing', () => {
      const c = new Cookies(
        {
          headers: {
            cookie: 'foo=bar',
          },
        },
        {},
      );
      expect(c.get('foo', { signed: true })).to.eql(undefined);
    });

    it('returns undefined when .sig cookie is missing', () => {
      const c = new Cookies(
        {
          headers: {
            cookie: 'foo=bar; foo.sig=bar',
          },
        },
        {},
      );
      expect(() => {
        c.get('foo', { signed: true });
      }).to.throw(Error, '.keys required for signed cookies');
    });
  });

  describe('cookies#set', () => {
    it('sets a cookie', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() {},
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar');

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; path=/; httponly'])).to.be.true;
    });

    it('fails to set a signed cookie without keys', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          protocol: 'https',
        },
        {
          getHeader() {},
          setHeader,
        },
      );

      expect(() => {
        c.set('foo', 'bar', { signed: true });
      }).to.throw(Error, '.keys required for signed cookies');
    });

    it('sets a signed cookie', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          protocol: 'https',
        },
        {
          getHeader() {},
          setHeader,
        },
        {
          keys: ['foo'],
        },
      );

      c.set('foo', 'bar', { signed: true });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; path=/; secure; httponly', 'foo.sig=58n4nqDbwygdLZwct9lAZjBSQK8; path=/; secure; httponly'])).to.be.true;
    });

    it('unsets a signature cookie when its signing key is no longer in rotation', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          protocol: 'https',
          headers: {
            cookie: 'foo=bar; foo.sig=58n4nqDbwygdLZwct9lAZjBSQK8',
          },
        },
        {
          getHeader() {},
          setHeader,
        },
        {
          keys: ['bar'],
        },
      );

      c.get('foo', { signed: true });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo.sig=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; secure; httponly'])).to.be.true;
    });

    it('resigns with a new signing if the used one is an old one', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          protocol: 'https',
          headers: {
            cookie: 'foo=bar; foo.sig=58n4nqDbwygdLZwct9lAZjBSQK8',
          },
        },
        {
          getHeader() {},
          setHeader,
        },
        {
          keys: ['bar', 'foo'],
        },
      );

      c.get('foo', { signed: true });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo.sig=c3oxDbH35HWaeACRK7qMCmIkU8I; path=/; secure; httponly'])).to.be.true;
    });

    it('keeps existing headers', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() { return ['foo']; },
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar');

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo', 'foo=bar; path=/; httponly'])).to.be.true;
    });

    it('keeps existing header', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() { return 'foo'; },
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar');

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo', 'foo=bar; path=/; httponly'])).to.be.true;
    });

    it('sets expiration based on maxAge', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() {},
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar', {
        maxAge: 10,
        signed: false,
        httpOnly: false,
      });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; path=/; expires=Fri, 27 Sep 2019 17:12:00 GMT'])).to.be.true;
    });

    it('sets an explicit path', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() {},
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar', {
        path: '/foo',
        signed: false,
        httpOnly: false,
      });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; path=/foo'])).to.be.true;
    });

    it('sets a domain', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() {},
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar', {
        path: null,
        domain: 'op.example.com',
        signed: false,
        httpOnly: false,
      });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; domain=op.example.com'])).to.be.true;
    });

    it('sets samesite', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {},
        {
          getHeader() {},
          setHeader,
        },
        { secure: false, keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar', {
        path: null,
        sameSite: 'lax',
        signed: false,
        httpOnly: false,
      });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; samesite=lax'])).to.be.true;
    });

    it('sets secure', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          protocol: 'https',
        },
        {
          getHeader() {},
          setHeader,
        },
        { keys: ['foo', 'bar'] },
      );

      c.set('foo', 'bar', {
        path: null,
        secure: true,
        signed: false,
        httpOnly: false,
      });

      expect(setHeader.calledOnce).to.be.true;
      expect(setHeader.calledWith('Set-Cookie', ['foo=bar; secure'])).to.be.true;
    });

    it('will not send a secure cookie over insecure channel', () => {
      const setHeader = sinon.spy();
      const c = new Cookies(
        {
          connection: {
            encrypted: false,
          },
          protocol: 'http',
        },
        {
          getHeader() {},
          setHeader,
        },
        { keys: ['foo', 'bar'] },
      );

      expect(() => {
        c.set('foo', 'bar', { secure: true });
      }).to.throw(Error, 'Cannot send secure cookie over unencrypted connection');
    });

    ['', null, undefined, 0].forEach((falsy) => {
      it(`unsets a cookie when value is ${String(falsy)}`, () => {
        const setHeader = sinon.spy();
        const c = new Cookies(
          {},
          {
            getHeader() {},
            setHeader,
          },
          { secure: false, keys: ['foo', 'bar'] },
        );

        c.set('foo', falsy, {
          path: null,
          signed: false,
          httpOnly: false,
        });

        expect(setHeader.calledOnce).to.be.true;
        expect(setHeader.calledWith('Set-Cookie', ['foo=; expires=Thu, 01 Jan 1970 00:00:00 GMT'])).to.be.true;
      });
    });
  });
});
