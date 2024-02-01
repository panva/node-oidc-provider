export default (grant, requestParamScopes, resourceServers) => {
  const combinedScope = new Set();

  grant.getOIDCScopeFiltered(requestParamScopes)
    .split(' ')
    .filter(Boolean)
    .forEach(Set.prototype.add.bind(combinedScope));

  for (const resourceServer of Object.values(resourceServers)) {
    grant.getResourceScopeFiltered(resourceServer.identifier(), requestParamScopes)
      .split(' ')
      .filter(Boolean)
      .forEach(Set.prototype.add.bind(combinedScope));
  }

  return combinedScope;
};
