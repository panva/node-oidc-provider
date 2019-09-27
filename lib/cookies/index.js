const http = require('http');

const Keygrip = require('keygrip');

const cache = {};

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/; // eslint-disable-line no-control-regex

/**
 * RegExp to match Same-Site cookie attribute value.
 */

const sameSiteRegExp = /^(?:lax|none|strict)$/i;

function getPattern(name) {
  if (!cache[name]) {
    cache[name] = new RegExp(
      `(?:^|;) *${
        name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')
      }=([^;]*)`,
    );
  }

  return cache[name];
}

function pushCookie(headers, cookie) {
  if (cookie.overwrite) {
    for (let i = headers.length - 1; i >= 0; i--) { // eslint-disable-line no-plusplus
      if (headers[i].indexOf(`${cookie.name}=`) === 0) {
        headers.splice(i, 1);
      }
    }
  }

  headers.push(cookie.toHeader());
}

function Cookie(name, value, attrs) {
  /* istanbul ignore if */
  if (!fieldContentRegExp.test(name)) {
    throw new TypeError('argument name is invalid');
  }

  /* istanbul ignore if */
  if (value && !fieldContentRegExp.test(value)) {
    throw new TypeError('argument value is invalid');
  }

  if (!value) {
    this.expires = new Date(0);
  }

  this.name = name;
  this.value = value || '';

  Object.assign(this, attrs);

  /* istanbul ignore if */
  if (this.path && !fieldContentRegExp.test(this.path)) {
    throw new TypeError('option path is invalid');
  }

  /* istanbul ignore if */
  if (this.domain && !fieldContentRegExp.test(this.domain)) {
    throw new TypeError('option domain is invalid');
  }

  /* istanbul ignore if */
  if (this.sameSite && !sameSiteRegExp.test(this.sameSite)) {
    throw new TypeError('option sameSite is invalid');
  }
}

Cookie.prototype.path = '/';
Cookie.prototype.expires = undefined;
Cookie.prototype.domain = undefined;
Cookie.prototype.httpOnly = true;
Cookie.prototype.sameSite = false;
Cookie.prototype.secure = false;
Cookie.prototype.overwrite = false;

Cookie.prototype.toString = function toString() {
  return `${this.name}=${this.value}`;
};

Cookie.prototype.toHeader = function toHeader() {
  const header = [this.toString()];

  if (this.maxAge) {
    this.expires = new Date(Date.now() + this.maxAge);
  }

  if (this.path) {
    header.push(`path=${this.path}`);
  }

  if (this.expires) {
    header.push(`expires=${this.expires.toUTCString()}`);
  }

  if (this.domain) {
    header.push(`domain=${this.domain}`);
  }

  if (this.sameSite) {
    header.push(`samesite=${this.sameSite.toLowerCase()}`);
  }

  if (this.secure) {
    header.push('secure');
  }

  if (this.httpOnly) {
    header.push('httponly');
  }

  return header.join('; ');
};

function Cookies(request, response, options = {}) {
  this.secure = undefined;
  this.request = request;
  this.response = response;

  if (options.keys) {
    this.keys = Array.isArray(options.keys) ? new Keygrip(options.keys) : options.keys;
    this.secure = options.secure;
  }
}

Cookies.prototype.get = function get(name, opts) {
  const signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

  const header = this.request.headers.cookie;
  if (!header) {
    return undefined;
  }

  const match = header.match(getPattern(name));
  if (!match) {
    return undefined;
  }

  const [, value] = match;
  if (!opts || !signed) {
    return value;
  }

  const sigName = `${name}.sig`;
  const remote = this.get(sigName);
  if (!remote) {
    return undefined;
  }

  const data = `${name}=${value}`;

  if (!this.keys) {
    throw new Error('.keys required for signed cookies');
  }

  const index = this.keys.index(data, remote);

  // signing key is no longer in rotation, drop cookie
  if (index < 0) {
    this.set(sigName, null, { path: '/', signed: false });
    return undefined;
  }

  // signing key is no longer the first one used, re-sign cookie
  if (index > 0) {
    this.set(sigName, this.keys.sign(data), { signed: false });
  }

  return value;
};

Cookies.prototype.set = function set(name, value, opts) {
  const res = this.response;
  const req = this.request;
  let headers = res.getHeader('Set-Cookie') || [];
  const secure = this.secure !== undefined ? !!this.secure : req.protocol === 'https' || req.connection.encrypted;
  const cookie = new Cookie(name, value, opts);
  const signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

  if (typeof headers === 'string') {
    headers = [headers];
  }

  if (!secure && opts && opts.secure) {
    throw new Error('Cannot send secure cookie over unencrypted connection');
  }

  cookie.secure = secure;
  if (opts && opts.secure !== undefined) {
    cookie.secure = opts.secure;
  }

  pushCookie(headers, cookie);

  if (opts && signed) {
    if (!this.keys) {
      throw new Error('.keys required for signed cookies');
    }
    cookie.value = this.keys.sign(cookie.toString());
    cookie.name += '.sig';
    pushCookie(headers, cookie);
  }

  const setHeader = res.set ? http.OutgoingMessage.prototype.setHeader : res.setHeader;
  setHeader.call(res, 'Set-Cookie', headers);
  return this;
};

module.exports = Cookies;
