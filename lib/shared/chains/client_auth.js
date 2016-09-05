'use strict';

const compose = require('koa-compose');

const bodyParser = require('../selective_body');
const params = require('../get_params');
const rejectDupes = require('../check_dupes');
const getClientId = require('../find_client_id');
const loadClient = require('../load_client');
const tokenAuth = require('../token_auth');

module.exports = function clientAuthChain(provider, whitelist) {
  const auth = tokenAuth(provider);
  const parseBody = bodyParser('application/x-www-form-urlencoded');
  ['client_assertion', 'client_assertion_type', 'client_id', 'client_secret']
    .forEach(whitelist.add.bind(whitelist));
  const buildParams = params(whitelist);

  return compose([
    parseBody,
    buildParams,
    rejectDupes,
    getClientId,
    loadClient(provider),
    auth,
  ]);
};
