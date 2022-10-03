const conjunction = new Intl.ListFormat('en', { type: 'conjunction' });
const disjunction = new Intl.ListFormat('en', { type: 'disjunction' });

const formatter = {
  format(iterable, { type }) {
    if (type === 'conjunction') {
      return conjunction.format(iterable);
    }

    return disjunction.format(iterable);
  },
};

module.exports = {
  formatList(list, { type = 'conjunction' } = {}) {
    return formatter.format(list.map((w) => `'${w}'`), { type });
  },
  pluralize(word, count) {
    if (count === 1) {
      return word;
    }

    return `${word}s`;
  },
};
