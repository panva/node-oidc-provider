'use strict';

const compose = require('koa-compose');

const body = require('../selective_body');
const params = require('../get_params');
const dupes = require('../check_dupes');
const client = require('../find_client_id');
const loadClient = require('../load_client');
const tokenAuth = require('../token_auth');

module.exports = function clientAuthChain(provider, whitelist) {
  const auth = tokenAuth(provider);

  const bodyMiddleware = body({
    only: 'application/x-www-form-urlencoded',
    raise: true,
  });

  const getParams = params({
    whitelist,
  });

  return compose([
    bodyMiddleware,
    getParams,
    dupes,
    client,
    loadClient(provider),
    auth,
  ]);
};
