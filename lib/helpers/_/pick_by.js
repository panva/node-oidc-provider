export default (object, predicate) => {
  const result = {};
  Object.entries(object).forEach(([key, value]) => {
    if (predicate(value, key)) {
      result[key] = value;
    }
  });

  return result;
};
