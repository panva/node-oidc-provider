'use strict';

let compose = require('koa-compose');

let body = require('../selective_body');
let params = require('../get_params');
let dupes = require('../check_dupes');
let client = require('../find_client_id');
let loadClient = require('../load_client');
let tokenAuth = require('../token_auth');

module.exports = function(provider, whitelist) {

  let auth = tokenAuth(provider);

  let bodyMiddleware = body({
    only: 'application/x-www-form-urlencoded',
    raise: true,
  });

  let getParams = params({
    whitelist: whitelist,
  });

  return compose([
    bodyMiddleware,
    getParams,
    dupes,
    client,
    loadClient(provider),
    auth
  ]);
};
