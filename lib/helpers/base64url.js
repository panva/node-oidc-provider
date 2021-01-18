let encode;
let encodeBuffer;
if (Buffer.isEncoding('base64url')) {
  encode = (input, encoding = 'utf8') => Buffer.from(input, encoding).toString('base64url');
  encodeBuffer = (buf) => buf.toString('base64url');
} else {
  const fromBase64 = (base64) => base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  encode = (input, encoding = 'utf8') => fromBase64(Buffer.from(input, encoding).toString('base64'));
  encodeBuffer = (buf) => fromBase64(buf.toString('base64'));
}

const decode = (input) => Buffer.from(input, 'base64').toString('utf8');
const decodeToBuffer = (input) => Buffer.from(input, 'base64');

module.exports.decode = decode;
module.exports.decodeToBuffer = decodeToBuffer;
module.exports.encode = encode;
module.exports.encodeBuffer = encodeBuffer;
