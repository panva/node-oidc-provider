import * as crypto from 'node:crypto';

export default function certThumbprint(cert) {
  let data;
  if (cert instanceof crypto.X509Certificate) {
    data = cert.raw;
  } else {
    data = Buffer.from(
      cert.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s|=)/g, ''),
      'base64',
    );
  }

  return crypto.hash('sha256', data, 'base64url');
}
