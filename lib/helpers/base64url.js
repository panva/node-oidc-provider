export function encode(input, encoding = 'utf8') {
  return Buffer.from(input, encoding).toString('base64url');
}

export function encodeBuffer(buf) {
  return Buffer.prototype.base64urlSlice.call(buf, 0, buf.length);
}

export function decode(input) {
  return Buffer.from(input, 'base64').toString('utf8');
}
