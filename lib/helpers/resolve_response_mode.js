function resolve(responseType) {
  return typeof responseType === 'string' && responseType.includes('token') ? 'fragment' : 'query';
}

module.exports = resolve;
module.exports.isFrontChannel = (responseType) => (resolve(responseType) === 'fragment');
