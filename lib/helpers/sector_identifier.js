const { URL } = require('url');

const { InvalidClientMetadata } = require('./errors');

module.exports = ({ sectorIdentifierUri, redirectUris, subjectType }) => {
  if (subjectType === 'pairwise') {
    if (!sectorIdentifierUri) {
      const { 0: host, length } = [...new Set(redirectUris.map((uri) => new URL(uri).host))];

      if (length === 0) {
        throw new InvalidClientMetadata('sector_identifier_uri is required when redirect_uris hosts are not available');
      }

      if (length !== 1) {
        throw new InvalidClientMetadata('sector_identifier_uri is required when using multiple hosts in your redirect_uris');
      }

      return host;
    }
  }

  return sectorIdentifierUri ? new URL(sectorIdentifierUri).host : undefined;
};
