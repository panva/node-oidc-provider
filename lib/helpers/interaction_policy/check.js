/* eslint-disable no-param-reassign */

class Check {
  constructor(reason, description, error, check = () => {}, details = () => {}) {
    if (typeof error === 'function') {
      details = check;
      check = error;
      error = undefined;
    }
    this.reason = reason;
    this.description = description;
    this.error = error;
    this.details = details;
    this.check = check;
  }
}

Check.REQUEST_PROMPT = true;
Check.NO_NEED_TO_PROMPT = false;

export default Check;
