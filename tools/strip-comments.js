/*
 * Line-preserving comment stripper used to build the published package.
 *
 * Comments are replaced by the exact number of newlines they spanned, so every
 * line number in the published lib/ matches the line number in this repository
 * and stack traces reported by consumers stay actionable.
 *
 * Intentionally dependency-free: the release workflow packs without installing
 * devDependencies.
 */

const KEYWORDS_BEFORE_REGEX = new Set([
  'await', 'case', 'default', 'delete', 'do', 'else', 'in', 'instanceof', 'new',
  'of', 'return', 'throw', 'typeof', 'void', 'yield',
]);

const isIdentifierChar = (c) => c === '_' || c === '$'
  || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');

/**
 * Decides whether a `/` at this point starts a regular expression literal
 * rather than a division operator, based on the preceding significant token.
 */
function startsRegExp(lastToken) {
  if (lastToken === undefined) return true;
  if (lastToken.type === 'name') return KEYWORDS_BEFORE_REGEX.has(lastToken.text);
  if (lastToken.type === 'value') return false;
  return lastToken.text !== ')' && lastToken.text !== ']';
}

export function stripComments(code) {
  const { length } = code;
  let out = '';
  let i = 0;
  let lastToken;

  // Tracks nesting of template literals and the `${ }` interpolations inside
  // them. `template` means we are scanning literal chunks, `code` means we are
  // inside an interpolation (or at the top level) and must count braces so we
  // know which `}` closes it.
  const modes = [{ type: 'code', depth: 0 }];

  while (i < length) {
    const mode = modes[modes.length - 1];

    if (mode.type === 'template') {
      const c = code[i];
      if (c === '\\') { out += code.slice(i, i + 2); i += 2; continue; }
      if (c === '`') { out += c; i += 1; modes.pop(); lastToken = { type: 'value', text: '`' }; continue; }
      if (c === '$' && code[i + 1] === '{') {
        out += '${'; i += 2;
        modes.push({ type: 'code', depth: 0 });
        lastToken = undefined;
        continue;
      }
      out += c; i += 1;
      continue;
    }

    const c = code[i];

    if (c === '/' && code[i + 1] === '*') {
      const end = code.indexOf('*/', i + 2);
      const stop = end === -1 ? length : end + 2;
      let newlines = 0;
      for (let k = i; k < stop; k += 1) if (code[k] === '\n') newlines += 1;
      // a comment separates the tokens either side of it, so something has to
      // remain in its place - `typeof/* x */foo` must not become `typeoffoo`.
      // Newlines do that job and keep line numbers intact; a comment that spans
      // none needs a space.
      out += newlines ? '\n'.repeat(newlines) : ' ';
      i = stop;
      continue;
    }

    if (c === '/' && code[i + 1] === '/') {
      let end = code.indexOf('\n', i);
      if (end === -1) end = length;
      i = end; // leave the newline itself in place
      continue;
    }

    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < length) {
        if (code[j] === '\\') { j += 2; continue; }
        if (code[j] === c) { j += 1; break; }
        j += 1;
      }
      out += code.slice(i, j);
      lastToken = { type: 'value', text: c };
      i = j;
      continue;
    }

    if (c === '`') {
      out += c;
      i += 1;
      modes.push({ type: 'template' });
      continue;
    }

    if (c === '/' && startsRegExp(lastToken)) {
      let j = i + 1;
      let inClass = false;
      while (j < length) {
        const d = code[j];
        if (d === '\\') { j += 2; continue; }
        if (d === '\n') break; // unterminated; treat defensively
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) { j += 1; break; }
        j += 1;
      }
      while (j < length && isIdentifierChar(code[j])) j += 1; // flags
      out += code.slice(i, j);
      lastToken = { type: 'value', text: '/' };
      i = j;
      continue;
    }

    if (isIdentifierChar(c)) {
      let j = i;
      while (j < length && isIdentifierChar(code[j])) j += 1;
      const text = code.slice(i, j);
      out += text;
      lastToken = { type: /^[0-9]/.test(text) ? 'value' : 'name', text };
      i = j;
      continue;
    }

    if (c === '{') {
      mode.depth += 1;
    } else if (c === '}') {
      if (mode.depth === 0 && modes.length > 1) {
        // closes a `${ ... }` interpolation
        out += c;
        i += 1;
        modes.pop();
        continue;
      }
      mode.depth -= 1;
    }

    out += c;
    if (!/\s/.test(c)) lastToken = { type: 'punct', text: c };
    i += 1;
  }

  return out;
}

export default stripComments;
