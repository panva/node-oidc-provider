/* eslint-disable max-classes-per-file */

class ReRenderError extends Error {
  constructor(message, userCode) {
    super(message);
    if (userCode) this.userCode = userCode;
    this.message = message;
    this.name = this.constructor.name;
    this.status = 200;
    this.statusCode = 200;
    this.expose = true;
    Error.captureStackTrace(this, this.constructor);
  }
}
class NotFoundError extends ReRenderError {
  constructor(userCode) {
    super('the code was not found', userCode);
  }
}
class ExpiredError extends ReRenderError {
  constructor(userCode) {
    super('the code has expired', userCode);
  }
}
class AbortedError extends ReRenderError {
  constructor() {
    super('the interaction was aborted');
  }
}
class AlreadyUsedError extends ReRenderError {
  constructor(userCode) {
    super('code has already been used', userCode);
  }
}
class NoCodeError extends ReRenderError {
  constructor() {
    super('no code submitted');
  }
}

module.exports = {
  AbortedError,
  AlreadyUsedError,
  ExpiredError,
  NoCodeError,
  NotFoundError,

  ReRenderError,
};
