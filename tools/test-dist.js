/*
 * Runs the test suite against the package that would actually be published,
 * rather than against the working tree.
 *
 * Two passes, because they catch different things:
 *
 * 1. Isolation. The tarball is installed with --omit=dev into an empty project
 *    and every published module is imported. Nothing of this repository is on
 *    the resolution path, so an import of a package that is no longer a runtime
 *    dependency, a wrong "type", or a file left out of `files` fails here
 *    rather than on someone's install.
 * 2. Behaviour. The suite runs against the extracted lib/, which needs this
 *    repository's devDependencies for mocha and friends - and therefore cannot
 *    tell you anything about the dependency closure. That is pass 1's job.
 *    Passing an existing tarball runs only pass 1, which lets the release job
 *    validate its exact artifact without installing devDependencies.
 *
 * Intentionally dependency-free, like tools/build.js.
 */

import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [suppliedTarball, ...extraArguments] = process.argv.slice(2);
if (extraArguments.length !== 0) throw new Error("expected at most one package tarball");
const runBehaviorTests = suppliedTarball === undefined;

const IMPORT_ALL = `import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const base = 'node_modules/oidc-provider/lib';
const files = [];
(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path);
    else if (path.endsWith('.js')) files.push(path);
  }
}(base));

const failures = [];
try {
  await import('oidc-provider');
} catch (err) {
  failures.push(\`  oidc-provider entry point: \${err.code ?? err.name} \${err.message.split('\\n')[0]}\`);
}

for (const file of files) {
  try {
    await import(pathToFileURL(file).href);
  } catch (err) {
    failures.push(\`  \${file}: \${err.code ?? err.name} \${err.message.split('\\n')[0]}\`);
  }
}

if (failures.length) {
  process.stderr.write(\`\${failures.length} published imports failed with only the declared dependencies:\\n\${failures.join('\\n')}\\n\`);
  process.exit(1);
}

process.stdout.write(\`the package entry point and all \${files.length} published modules import with only the declared dependencies\\n\`);
`;
const run = (cmd, args, cwd = root) => execFileSync(cmd, args, { cwd, stdio: "inherit" });

const staging = mkdtempSync(join(tmpdir(), "oidc-provider-dist-"));

try {
  let tarball;
  if (runBehaviorTests) {
    run("npm", ["run", "build"]);
    run("npm", ["pack", join(root, "dist"), "--pack-destination", staging]);

    const tarballs = readdirSync(staging).filter((entry) => entry.endsWith(".tgz"));
    if (tarballs.length !== 1) throw new Error(`npm pack produced ${tarballs.length} tarballs`);
    [tarball] = tarballs.map((entry) => join(staging, entry));
  } else {
    tarball = resolve(root, suppliedTarball);
  }
  run("tar", ["-xzf", tarball, "-C", staging]);

  const packed = join(staging, "package");
  const contents = readdirSync(packed).sort();
  process.stdout.write(`\nvalidated ${basename(tarball)} containing ${contents.join(", ")}\n\n`);

  // the MIT notices for the code vendored into lib/ have to travel with it
  for (const required of [
    "lib",
    "package.json",
    "README.md",
    "LICENSE.md",
    "THIRD-PARTY-NOTICES.md",
  ]) {
    if (!contents.includes(required)) throw new Error(`packed package is missing ${required}`);
  }
  if (contents.includes("types")) {
    throw new Error("source-only declaration templates must not be included in the package");
  }

  const sourceManifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const packedManifest = JSON.parse(readFileSync(join(packed, "package.json"), "utf8"));
  if (
    packedManifest.name !== sourceManifest.name ||
    packedManifest.version !== sourceManifest.version
  ) {
    throw new Error("the package tarball does not match the checked-out package name and version");
  }
  if (
    !runBehaviorTests &&
    process.env.GITHUB_REF_NAME !== undefined &&
    process.env.GITHUB_REF_NAME !== `v${packedManifest.version}`
  ) {
    throw new Error(
      `release tag ${process.env.GITHUB_REF_NAME} does not match ${packedManifest.name}@${packedManifest.version}`,
    );
  }

  // pass 1: nothing from this repository on the resolution path
  const isolated = join(staging, "isolated");
  mkdirSync(isolated, { recursive: true });
  writeFileSync(join(isolated, "package.json"), '{"name":"isolated","private":true}\n');
  run(
    "npm",
    ["install", "--install-strategy=nested", "--omit=dev", "--no-audit", "--no-fund", tarball],
    isolated,
  );
  writeFileSync(join(isolated, "import-all.mjs"), IMPORT_ALL);
  run(process.execPath, ["import-all.mjs"], isolated);

  if (runBehaviorTests) {
    // pass 2: the suite reads test/ and lib/ as siblings, and tools/views/*.eta for the
    // template drift check; node_modules is borrowed rather than reinstalled
    const work = join(staging, "work");
    cpSync(join(packed, "lib"), join(work, "lib"), { recursive: true });
    cpSync(join(root, "test"), join(work, "test"), { recursive: true });
    cpSync(join(root, "tools"), join(work, "tools"), { recursive: true });
    cpSync(join(root, "package.json"), join(work, "package.json"));
    symlinkSync(
      join(root, "node_modules"),
      join(work, "node_modules"),
      process.platform === "win32" ? "junction" : "dir",
    );

    run(process.execPath, ["./test/run"], work);
  }
} finally {
  rmSync(staging, { recursive: true, force: true });
}
