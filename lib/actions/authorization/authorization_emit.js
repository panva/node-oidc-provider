'use strict';

module.exports = provider => function* authorizationEmit(next) {
  if (this.oidc.result) {
    provider.emit('interaction.ended', this);
  } else {
    provider.emit('authorization.accepted', this);
  }
  yield next;
};
