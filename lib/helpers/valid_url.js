export function isHttpsUri(uri) {
  return URL.parse(uri)?.protocol === 'https:';
}

export function isWebUri(uri) {
  const protocol = URL.parse(uri)?.protocol;
  return protocol === 'https:' || protocol === 'http:';
}
