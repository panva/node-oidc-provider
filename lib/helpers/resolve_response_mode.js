export default function resolve(responseType) {
  return typeof responseType === 'string' && responseType.includes('token') ? 'fragment' : 'query';
}

export function isFrontChannel(responseType) {
  return resolve(responseType) === 'fragment';
}
