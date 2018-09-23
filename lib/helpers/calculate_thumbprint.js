const { createHash } = require('crypto');

const base64url = require('base64url');

module.exports = function getS256Thumbprint(cert) {
  const normalized = cert.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s|=)/g, '');
  return base64url(createHash('sha256').update(Buffer.from(normalized, 'base64')).digest());
};
