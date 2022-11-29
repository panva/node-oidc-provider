export default function apply(mixins) {
  const klass = mixins.pop();
  return mixins.reduce((mixed, mixin) => mixin(mixed), klass);
}
