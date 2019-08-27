let formatter;
if (Intl && Intl.ListFormat) {
  formatter = new Intl.ListFormat('en');
} else {
  formatter = {
    format(iterable) {
      const last = iterable.pop();
      switch (iterable.length) { // length after pop;
        case 0:
          return last || '';
        case 1:
          return `${iterable[0]} and ${last}`;
        default:
          return `${iterable.join(', ')}, and ${last}`;
      }
    },
  };
}

module.exports = {
  formatList(list) {
    return formatter.format(list.map((w) => `'${w}'`));
  },
  pluralize(word, count) {
    if (count === 1) {
      return word;
    }

    return `${word}s`;
  },
};
