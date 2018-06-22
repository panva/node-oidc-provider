const { URL } = require('url');

const { InvalidClientMetadata } = require('./errors');

module.exports = ({ sectorIdentifierUri, redirectUris, subjectType }) => {
  if (subjectType === 'pairwise' && !sectorIdentifierUri) {
    const hosts = redirectUris
      .map(uri => new URL(uri).host)
      .filter((value, index, self) => self.indexOf(value) === index);

    if (hosts.length !== 1) {
      throw new InvalidClientMetadata('sector_identifier_uri is required when using multiple hosts in your redirect_uris');
    }

    return hosts[0];
  }

  if (sectorIdentifierUri) {
    return new URL(sectorIdentifierUri).host;
  }

  return undefined;
};
