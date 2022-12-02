/* eslint-disable no-param-reassign */

export default (object, predicate) => {
  Object.entries(object).forEach(([key, value]) => {
    if (predicate(value, key)) {
      delete object[key];
    }
  });

  return object;
};
