/* eslint-disable global-require */

if (process.env.FAPI) {
  require('./fapi');
} else {
  require('./oidc');
}
