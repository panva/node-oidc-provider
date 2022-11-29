import { nanoid, customAlphabet } from 'nanoid';

export default (length, charset) => {
  if (charset) {
    return customAlphabet(charset, length)();
  }

  return nanoid(length);
};
