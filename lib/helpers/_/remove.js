module.exports = (array, predicate) => {
  const remove = [];
  array.forEach((value, index) => {
    if (predicate(value, index, array)) {
      remove.unshift(index);
    }
  });
  remove.forEach((i) => array.splice(i, 1));
};
