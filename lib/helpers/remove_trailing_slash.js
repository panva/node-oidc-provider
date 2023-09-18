export default function removeTrailingSlack(uri) {
  return uri.endsWith('/') ? uri.slice(0, -1) : uri;
}
