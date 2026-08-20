const SCOPE_SYNTAX = /^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/u;

export default function isValidScope(scope) {
  return scope === undefined || (typeof scope === 'string' && SCOPE_SYNTAX.test(scope));
}
