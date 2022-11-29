import { InvalidRequest } from './errors.js';

const check = /[^\w.\-~]/;

export default (input, param) => {
  if (input.length < 43) {
    throw new InvalidRequest(`${param} must be a string with a minimum length of 43 characters`);
  }

  if (input.length > 128) {
    throw new InvalidRequest(`${param} must be a string with a maximum length of 128 characters`);
  }

  if (check.test(input)) {
    throw new InvalidRequest(`${param} contains invalid characters`);
  }
};
