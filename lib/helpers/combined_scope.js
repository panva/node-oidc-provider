module.exports = (grant, requestParamScopes, resourceServers) => {
  const combinedScope = new Set();

  grant.getOIDCScopeFiltered(requestParamScopes)
    .split(' ')
    .forEach(Set.prototype.add.bind(combinedScope));

  // eslint-disable-next-line no-restricted-syntax
  for (const resourceServer of Object.values(resourceServers)) {
    grant.getResourceScopeFiltered(resourceServer.identifier(), requestParamScopes)
      .split(' ')
      .forEach(Set.prototype.add.bind(combinedScope));
  }

  return combinedScope;
};
