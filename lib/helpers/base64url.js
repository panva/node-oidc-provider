export function encode(input, encoding = 'utf8') {
  return Buffer.from(input, encoding).toString('base64url');
}

export function encodeBuffer(buf) {
  return buf.toString('base64url');
}

export function decode(input) {
  return Buffer.from(input, 'base64').toString('utf8');
}

export function decodeToBuffer(input) {
  return Buffer.from(input, 'base64');
}
