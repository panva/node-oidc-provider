import { createHash } from 'node:crypto';

import * as base64url from './base64url.js';

const normalize = (cert) => cert.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s|=)/g, '');
const calculate = (hash, cert) => base64url.encodeBuffer(createHash(hash).update(Buffer.from(normalize(cert), 'base64')).digest());

export const x5t = calculate.bind(undefined, 'sha1');
export const x5tS256 = calculate.bind(undefined, 'sha256');
