import instance from './weak_cache.js';

function getClientCredentials(provider, token) {
  if (!instance(provider).grantTypeHandlers.has('client_credentials')) {
    return undefined;
  }
  return provider.ClientCredentials.find(token);
}

function getRefreshToken(provider, token) {
  if (!instance(provider).grantTypeHandlers.has('refresh_token')) {
    return undefined;
  }
  return provider.RefreshToken.find(token);
}

function findResult(results) {
  return results.find((found) => !!found);
}

export async function findToken(provider, tokenValue, tokenTypeHint) {
  switch (tokenTypeHint) {
    case 'access_token':
    case 'urn:ietf:params:oauth:token-type:access_token':
      return Promise.all([
        provider.AccessToken.find(tokenValue),
        getClientCredentials(provider, tokenValue),
      ])
        .then(findResult)
        .then((result) => result || getRefreshToken(provider, tokenValue));
    case 'refresh_token':
    case 'urn:ietf:params:oauth:token-type:refresh_token':
      return await getRefreshToken(provider, tokenValue) || Promise.all([
        provider.AccessToken.find(tokenValue),
        getClientCredentials(provider, tokenValue),
      ]).then(findResult);
    default:
      return Promise.all([
        provider.AccessToken.find(tokenValue),
        getClientCredentials(provider, tokenValue),
        getRefreshToken(provider, tokenValue),
      ]).then(findResult);
  }
}
