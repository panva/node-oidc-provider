const remove = require('./remove');

module.exports = (array, predicate) => {
  const clone = [...array];
  remove(clone, predicate);
  return clone;
};
