const cache = new WeakMap();

function properties(Model) {
  let result = cache.get(Model);
  if (result === undefined) {
    result = new Set(Model.IN_PAYLOAD);
    cache.set(Model, result);
  }
  return result;
}

export default function pick(Model, input) {
  if (input === null) {
    throw new TypeError('invalid model payload');
  }

  const source = Object(input);
  const allowed = properties(Model);
  const result = {};

  for (const key of Object.keys(source)) {
    if (allowed.has(key)) {
      Object.defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: source[key],
        writable: true,
      });
    }
  }

  return result;
}
