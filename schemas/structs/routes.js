const { struct } = require('../struct');
const { routes: defaults } = require('../../lib/helpers/defaults');

module.exports = struct({
  authorization: 'string & route',
  certificates: 'string & route',
  check_session: 'string & route',
  end_session: 'string & route',
  introspection: 'string & route',
  registration: 'string & route',
  revocation: 'string & route',
  token: 'string & route',
  userinfo: 'string & route',
}, {
  authorization: defaults.authorization,
  certificates: defaults.certificates,
  check_session: defaults.check_session,
  end_session: defaults.end_session,
  introspection: defaults.introspection,
  registration: defaults.registration,
  revocation: defaults.revocation,
  token: defaults.token,
  userinfo: defaults.userinfo,
});
