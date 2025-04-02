const map = new WeakMap();

export function get(ctx) {
  return map.get(ctx);
}

export function set(ctx, value) {
  return map.set(ctx, value);
}

export default get;
