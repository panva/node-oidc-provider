module.exports = (object = {}, ...properties) => {
  const result = {};
  properties.forEach((property) => {
    if (Object.prototype.hasOwnProperty.call(object, property)) {
      result[property] = object[property];
    }
  });

  return result;
};
