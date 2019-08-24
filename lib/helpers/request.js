const got = require('got');
const defaultsDeep = require('lodash/defaultsDeep');

const pkg = require('../../package.json');

const { httpOptions } = require('./defaults');
const instance = require('./weak_cache');

const USER_AGENT = `${pkg.name}/${pkg.version} (${pkg.homepage})`;

const DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': USER_AGENT },
  retry: 0,
  throwHttpErrors: false,
  timeout: 2500,
};

module.exports = async function request(options) {
  const optsFn = instance(this).configuration('httpOptions');

  let opts = defaultsDeep(options, DEFAULT_HTTP_OPTIONS);
  if (optsFn !== httpOptions) {
    opts = optsFn(opts);
  }

  return got(opts);
};
