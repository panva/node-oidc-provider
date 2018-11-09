function resolve(responseType) {
  return String(responseType).includes('token') ? 'fragment' : 'query';
}

module.exports = resolve;
module.exports.isImplicit = responseType => (resolve(responseType) === 'fragment');
