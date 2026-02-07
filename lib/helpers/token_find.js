export function createTokenFinder(provider, grantTypeHandlers) {
  const { AccessToken, ClientCredentials, RefreshToken } = provider;

  function getAccessToken(token) {
    return AccessToken.find(token);
  }

  function getClientCredentials(token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  return async function findTokenByHint(tokenValue, tokenTypeHint) {
    switch (tokenTypeHint) {
      case 'access_token':
      case 'urn:ietf:params:oauth:token-type:access_token':
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
        ])
          .then(findResult)
          .then((result) => result || getRefreshToken(tokenValue));
      case 'refresh_token':
      case 'urn:ietf:params:oauth:token-type:refresh_token':
        return getRefreshToken(tokenValue)
          .then((result) => result || Promise.all([
            getAccessToken(tokenValue),
            getClientCredentials(tokenValue),
          ]).then(findResult));
      default:
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
          getRefreshToken(tokenValue),
        ]).then(findResult);
    }
  };
}
