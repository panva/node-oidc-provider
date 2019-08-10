const b64uRegExp = /^[a-zA-Z0-9_-]*$/;

const fromBase64 = (base64) => base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const toBase64 = (base64url) => base64url.replace(/-/g, '+').replace(/_/g, '/');

const encode = (input, encoding = 'utf8') => fromBase64(Buffer.from(input, encoding).toString('base64'));

const encodeBuffer = (buf) => fromBase64(buf.toString('base64'));

const decode = (input) => {
  if (!b64uRegExp.test(input)) {
    throw new TypeError('input is not a valid base64url encoded string');
  }
  return Buffer.from(toBase64(input), 'base64').toString('utf8');
};

const decodeToBuffer = (input) => {
  if (!b64uRegExp.test(input)) {
    throw new TypeError('input is not a valid base64url encoded string');
  }
  return Buffer.from(toBase64(input), 'base64');
};

module.exports.decode = decode;
module.exports.decodeToBuffer = decodeToBuffer;
module.exports.encode = encode;
module.exports.encodeBuffer = encodeBuffer;
