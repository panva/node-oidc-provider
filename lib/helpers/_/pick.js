export default (object = {}, ...properties) => {
  const result = {};
  properties.forEach((property) => {
    if (Object.hasOwn(object, property)) {
      result[property] = object[property];
    }
  });

  return result;
};
