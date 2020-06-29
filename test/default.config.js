const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const { JWA } = require('../lib/consts');

module.exports = merge({
  claims: {
    address: {
      address: null,
    },
    email: {
      email: null,
      email_verified: null,
    },
    phone: {
      phone_number: null,
      phone_number_verified: null,
    },
    profile: {
      birthdate: null,
      family_name: null,
      gender: null,
      given_name: null,
      locale: null,
      middle_name: null,
      name: null,
      nickname: null,
      picture: null,
      preferred_username: null,
      profile: null,
      updated_at: null,
      website: null,
      zoneinfo: null,
    },
  },
  cookies: {
    long: {
      signed: true,
    },
    short: {
      signed: true,
    },
    keys: ['foo'],
  },
  responseTypes: [
    'code id_token token',
    'code id_token',
    'code token',
    'code',
    'id_token token',
    'id_token',
    'none',
  ],
  features: {},
  whitelistedJWA: cloneDeep(JWA),
}, global.TEST_CONFIGURATION_DEFAULTS);
