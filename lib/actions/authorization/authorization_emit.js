'use strict';

const Debug = require('debug');

const accepted = new Debug('oidc-provider:authentication:accepted');
const resumed = new Debug('oidc-provider:authentication:resumed');

module.exports = provider => function* authorizationEmit(next) {
  if (this.oidc.result) {
    resumed('uuid=%s %o', this.oidc.uuid, this.oidc.result);
    provider.emit('interaction.ended', this);
  } else {
    accepted('uuid=%s %o', this.oidc.uuid, this.oidc.params);
    provider.emit('authorization.accepted', this);
  }
  yield next;
};
