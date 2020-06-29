/* eslint-disable no-param-reassign */

module.exports = (object, predicate) => {
  Object.entries(object).forEach(([key, value]) => {
    if (predicate(value, key)) { // TODO: swap predicate arguments
      delete object[key];
    }
  });

  return object;
};
