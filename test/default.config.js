import cloneDeep from 'lodash/cloneDeep.js';

import { JWA } from '../lib/consts/index.js';

export const enabledJWA = cloneDeep({ ...JWA });

export default () => ({
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
  enabledJWA: cloneDeep({ ...JWA }),
  pkce: {
    required: () => false,
  },
});
