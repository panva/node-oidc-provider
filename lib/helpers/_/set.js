import isPlainObject from './is_plain_object.js';

export default (object, path, value) => {
  const properties = path.split('.');
  if (properties.includes('__proto__') || properties.includes('constructor')) {
    throw new TypeError('__proto__ and constructor cannot be set');
  }
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
