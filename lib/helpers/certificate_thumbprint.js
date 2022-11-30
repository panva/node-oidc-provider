import { createHash } from 'node:crypto';

import * as base64url from './base64url.js';

export default function certThumbprint(cert) {
  return base64url.encodeBuffer(
    createHash('sha256')
      .update(
        Buffer.from(
          cert.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s|=)/g, ''),
          'base64',
        ),
      )
      .digest(),
  );
}
