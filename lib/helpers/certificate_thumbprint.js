import { createHash, X509Certificate } from 'node:crypto';

import * as base64url from './base64url.js';

export default function certThumbprint(cert) {
  let digest;
  if (cert instanceof X509Certificate) {
    digest = createHash('sha256').update(cert.raw).digest();
  } else {
    digest = createHash('sha256')
      .update(
        Buffer.from(
          cert.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s|=)/g, ''),
          'base64',
        ),
      )
      .digest();
  }

  return base64url.encodeBuffer(digest);
}
