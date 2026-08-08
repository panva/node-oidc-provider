/*
 * Builds the publishable package into dist/.
 *
 * The working tree is never modified: `npm publish` (and `npm stage publish`)
 * is pointed at dist/ instead of the repository root, so a failed or
 * interrupted release cannot leave stripped sources behind.
 *
 * Intentionally dependency-free: the release workflow packs without installing
 * devDependencies.
 */

import { execFileSync } from 'node:child_process';
import {
  cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { stripComments } from './strip-comments.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

const countLines = (str) => {
  let n = 1;
  for (let i = 0; i < str.length; i += 1) if (str[i] === '\n') n += 1;
  return n;
};

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

let before = 0;
let after = 0;
let count = 0;

(function walk(dir, rel) {
  for (const entry of readdirSync(dir)) {
    const from = join(dir, entry);
    const relative = join(rel, entry);
    if (statSync(from).isDirectory()) {
      walk(from, relative);
      continue;
    }

    const to = join(dist, relative);
    mkdirSync(dirname(to), { recursive: true });

    if (!entry.endsWith('.js')) {
      cpSync(from, to);
      continue;
    }

    const source = readFileSync(from, 'utf8');
    const stripped = stripComments(source);

    // Line numbers must survive so consumer stack traces stay actionable.
    if (countLines(source) !== countLines(stripped)) {
      throw new Error(`${relative}: line count changed ${countLines(source)} -> ${countLines(stripped)}`);
    }

    writeFileSync(to, stripped);
    execFileSync(process.execPath, ['--check', to], { stdio: 'pipe' });

    before += Buffer.byteLength(source);
    after += Buffer.byteLength(stripped);
    count += 1;
  }
}(join(root, 'lib'), 'lib'));

// npm always includes package.json, README and LICENSE, but nothing else, so
// the third party notices have to be listed to be packed
const NOTICES = 'THIRD-PARTY-NOTICES.md';

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
delete pkg.scripts;
delete pkg.devDependencies;
pkg.files = [...pkg.files, NOTICES];
writeFileSync(join(dist, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);

for (const file of ['README.md', 'LICENSE.md', NOTICES]) {
  cpSync(join(root, file), join(dist, file));
}

const saved = before - after;
process.stdout.write(`built dist/ from ${count} files: ${before} -> ${after} bytes (-${saved}, ${((100 * saved) / before).toFixed(1)}%)\n`);
