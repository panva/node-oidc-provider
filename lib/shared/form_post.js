'use strict';

module.exports = function getFormPost(provider) {
  return function formPost(action, inputs) {
    this.type = 'html';
    this.status = 200;
    provider.configuration('formPost').call(this, action, inputs);
  };
};
