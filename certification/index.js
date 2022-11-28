/* eslint-disable global-require */

if (process.env.FAPI) {
  require('./fapi/index.js');
} else {
  require('./oidc/index.js');
}
