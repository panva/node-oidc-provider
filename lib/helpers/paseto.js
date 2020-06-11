const { sign: signOneShot } = require('crypto');

const base64url = require('./base64url');

const PURPOSE = 'public';
const VERSION = 'v2';

const le64 = (n) => {
  const up = ~~(n / 0xFFFFFFFF); // eslint-disable-line no-bitwise
  const dn = (n % 0xFFFFFFFF) - up;

  const buf = Buffer.allocUnsafe(8);

  buf.writeUInt32LE(up, 4);
  buf.writeUInt32LE(dn, 0);

  return buf;
};

const pae = (...pieces) => {
  let accumulator = le64(pieces.length);
  for (let piece of pieces) { // eslint-disable-line no-restricted-syntax
    piece = Buffer.from(piece, 'utf8');
    const len = le64(Buffer.byteLength(piece));
    accumulator = Buffer.concat([accumulator, len, piece]);
  }
  return accumulator;
};

const pack = (header, payload, footer) => {
  if (footer.length !== 0) {
    return `${header}${base64url.encodeBuffer(Buffer.concat(payload))}.${base64url.encodeBuffer(footer)}`;
  }

  return `${header}${base64url.encodeBuffer(Buffer.concat(payload))}`;
};

const decode = (paseto) => {
  const {
    0: version, 1: purpose, 2: sPayload, length,
  } = paseto.split('.');

  if (!(length === 3 || length === 4) || version !== VERSION || purpose !== PURPOSE) {
    throw new TypeError('not a v2.public PASETO');
  }

  return JSON.parse(base64url.decodeToBuffer(sPayload).slice(0, -64));
};

const sign = ({ payload, footer }, key) => {
  const h = `${VERSION}.${PURPOSE}.`;
  const m = Buffer.from(JSON.stringify(payload), 'utf8');
  let f;
  if (typeof footer === 'string') {
    f = Buffer.from(footer, 'utf8');
  } else if (Buffer.isBuffer(footer)) {
    f = footer;
  } else if (footer) {
    f = Buffer.from(JSON.stringify(footer));
  } else {
    f = Buffer.from('');
  }
  const sig = signOneShot(undefined, pae(h, m, f), key);
  return pack(h, [m, sig], f);
};

module.exports = { sign, decode };
