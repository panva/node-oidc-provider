const isPlainObject = require('./is_plain_object');

module.exports = (object, path, value) => {
  const properties = path.split('.');
  let current = object;
  properties.forEach((property, i) => {
    if (i + 1 === properties.length) {
      current[property] = value;
    } else if (!(property in current) || !isPlainObject(current[property])) {
      current[property] = {};
    }

    current = current[property];
  });
};
