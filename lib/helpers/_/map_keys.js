module.exports = (object, iteratee) => {
  const result = {};

  Object.entries(object).forEach(([key, value]) => {
    result[iteratee(value, key, object)] = value;
  });

  return result;
};
