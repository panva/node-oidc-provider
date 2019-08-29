let formatter;
if (Intl && Intl.ListFormat) {
  const conjunction = new Intl.ListFormat('en', { type: 'conjunction' });
  const disjunction = new Intl.ListFormat('en', { type: 'disjunction' });
  formatter = {
    format(iterable, { type }) {
      if (type === 'conjunction') {
        return conjunction.format(iterable);
      }

      return disjunction.format(iterable);
    },
  };
} else {
  formatter = {
    format(iterable, { type }) {
      const last = iterable.pop();
      switch (iterable.length) { // length after pop;
        case 0:
          return last || '';
        case 1:
          return `${iterable[0]} ${type === 'conjunction' ? 'and' : 'or'} ${last}`;
        default:
          return `${iterable.join(', ')}, ${type === 'conjunction' ? 'and' : 'or'} ${last}`;
      }
    },
  };
}

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
