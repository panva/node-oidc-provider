module.exports = (object, predicate) => {
  const result = {};
  Object.entries(object).forEach(([key, value]) => {
    if (predicate(value, key)) { // TODO: swap predicate arguments
      result[key] = value;
    }
  });

  return result;
};
