const { nanoid, customAlphabet } = require('nanoid');

module.exports = (length, charset) => {
  if (charset) {
    return customAlphabet(charset, length)();
  }

  return nanoid(length);
};
