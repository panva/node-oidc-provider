const cache = new WeakMap();

export default function payloadProperties(Model) {
  let properties = cache.get(Model);
  if (!properties) {
    properties = new Set(Model.IN_PAYLOAD);
    cache.set(Model, properties);
  }
  return properties;
}
