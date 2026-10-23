#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

const SCHEMA_VERSION = 3;
const STATUS_SCHEMA_VERSION = 1;
const GRANTS_PATH = "lib/helpers/grants.d.ts";
const FRAGMENT_NAMES = ["contracts", "providerMembers", "relatedContracts", "clientAuthMethods", "oidcContext"];
const FILE_PATHS = [GRANTS_PATH, "oidc-provider-tests.ts"];
const REGIONS = {
    contracts: {
        start: "// BEGIN GENERATED OIDC-PROVIDER CONTRACTS",
        end: "// END GENERATED OIDC-PROVIDER CONTRACTS",
    },
    providerMembers: {
        start: "    // BEGIN GENERATED OIDC-PROVIDER MEMBERS",
        end: "    // END GENERATED OIDC-PROVIDER MEMBERS",
    },
    clientAuthMethods: {
        start: "// BEGIN GENERATED OIDC-PROVIDER CLIENT AUTH METHODS",
        end: "// END GENERATED OIDC-PROVIDER CLIENT AUTH METHODS",
        legacy: /^export type ClientAuthMethod =[\s\S]*?;$/gm,
        declaration: /^export type ClientAuthMethod\s*=/gm,
    },
    oidcContext: {
        start: "// BEGIN GENERATED OIDC-PROVIDER OIDC CONTEXT",
        end: "// END GENERATED OIDC-PROVIDER OIDC CONTEXT",
        legacy: /^declare class OIDCContext \{[\s\S]*?^\}$/gm,
        declaration: /^declare class OIDCContext\s*\{/gm,
    },
    relatedContracts: {
        start: "// BEGIN GENERATED OIDC-PROVIDER RELATED CONTRACTS",
        end: "// END GENERATED OIDC-PROVIDER RELATED CONTRACTS",
    },
};
const PROVENANCE_PATTERN = /^\/\/ oidc-provider types artifact .*; schema \d+; sha256 [a-f0-9]{64}\n?/m;

function fail(message) {
    console.error(`update-types: ${message}`);
    process.exit(1);
}

function usage() {
    return "usage: node update-types.mjs --package-dir <absolute-path> [--check | --status] (--artifact <path> | <provider-checkout>)";
}

function parseArguments(argv) {
    let mode = "update";
    let artifactPath;
    let packageDirectory;
    const positional = [];

    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === "--check" || argument === "--status") {
            if (mode !== "update") fail("--check and --status cannot be combined");
            mode = argument.slice(2);
        } else if (argument === "--package-dir") {
            if (packageDirectory !== undefined) fail("--package-dir may only be specified once");
            packageDirectory = argv[index + 1];
            if (!packageDirectory || !isAbsolute(packageDirectory)) fail("--package-dir requires an absolute path");
            index += 1;
        } else if (argument === "--artifact") {
            if (artifactPath !== undefined) fail("--artifact may only be specified once");
            artifactPath = argv[index + 1];
            if (!artifactPath || artifactPath.startsWith("-")) fail("--artifact requires a path");
            index += 1;
        } else if (argument.startsWith("-")) {
            fail(`unknown option ${JSON.stringify(argument)}`);
        } else {
            positional.push(argument);
        }
    }

    if ((artifactPath === undefined && positional.length !== 1) || (artifactPath !== undefined && positional.length)) {
        fail(usage());
    }

    if (packageDirectory === undefined) fail("--package-dir is required");

    return {
        artifactPath: artifactPath === undefined ? undefined : resolve(artifactPath),
        mode,
        packageDirectory,
        providerDirectory: artifactPath === undefined ? resolve(positional[0]) : undefined,
    };
}

function readJson(path, label) {
    try {
        return JSON.parse(readFileSync(path, "utf8"));
    } catch (error) {
        fail(`could not read ${label} at ${path}: ${error.message}`);
    }
}

function versionLine(version, label) {
    if (typeof version !== "string") {
        fail(`${label} has an invalid version: ${JSON.stringify(version)}`);
    }
    const match = /^(\d+)\.(\d+)(?:\.|$)/.exec(version);
    if (!match) {
        fail(`${label} has an invalid version: ${JSON.stringify(version)}`);
    }
    return { major: Number(match[1]), minor: Number(match[2]) };
}

function compareVersionLines(left, right) {
    return left.major - right.major || left.minor - right.minor;
}

function targetTypesVersion(providerLine) {
    return `${providerLine.major}.${providerLine.minor}.9999`;
}

function exactKeys(value, expected, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        fail(`${label} must be an object`);
    }

    const actual = Object.keys(value).sort();
    const sortedExpected = [...expected].sort();
    if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
        fail(`${label} must have exactly these keys: ${sortedExpected.join(", ")}`);
    }
}

function declarationText(value, label) {
    if (typeof value !== "string" || !value.trim()) {
        fail(`${label} must be a non-empty string`);
    }
    if (value.includes("\r")) {
        fail(`${label} must use LF line endings`);
    }
    return value;
}

function dprintExecutable(repositoryDirectory) {
    const directory = resolve(repositoryDirectory, "node_modules", "dprint");
    const packageMetadata = readJson(resolve(directory, "package.json"), "dprint package.json");
    const declared = typeof packageMetadata.bin === "string" ? packageMetadata.bin : packageMetadata.bin?.dprint;
    if (typeof declared !== "string" || !declared) {
        fail("dprint package.json must declare a dprint executable");
    }

    const executable = resolve(directory, declared);
    const relativeExecutable = relative(directory, executable);
    if (
        !relativeExecutable
        || isAbsolute(relativeExecutable)
        || relativeExecutable === ".."
        || relativeExecutable.startsWith(`..${sep}`)
    ) {
        fail("dprint package.json declares an invalid executable path");
    }
    return executable;
}

function canonicalContent(indexFragments, files) {
    return JSON.stringify({
        indexFragments: Object.fromEntries(FRAGMENT_NAMES.map((name) => [name, indexFragments[name]])),
        files: Object.fromEntries(FILE_PATHS.map((path) => [path, files[path]])),
    });
}

function validateArtifact(payload, expectedProviderVersion) {
    exactKeys(
        payload,
        ["schemaVersion", "providerVersion", "hash", "indexFragments", "files"],
        "provider types artifact",
    );
    if (payload.schemaVersion !== SCHEMA_VERSION) {
        fail(`unsupported provider types schema version ${JSON.stringify(payload.schemaVersion)}`);
    }
    versionLine(payload.providerVersion, "provider types artifact");
    if (expectedProviderVersion !== undefined && payload.providerVersion !== expectedProviderVersion) {
        fail(
            `provider types artifact is for ${
                JSON.stringify(payload.providerVersion)
            }, expected ${expectedProviderVersion}`,
        );
    }
    if (typeof payload.hash !== "string" || !/^[a-f0-9]{64}$/.test(payload.hash)) {
        fail("provider types artifact hash must be a lowercase hexadecimal SHA-256 digest");
    }

    exactKeys(payload.indexFragments, FRAGMENT_NAMES, "provider types indexFragments");
    exactKeys(payload.files, FILE_PATHS, "provider types files");
    for (const name of FRAGMENT_NAMES) {
        declarationText(payload.indexFragments[name], `provider types indexFragments.${name}`);
    }
    for (const path of FILE_PATHS) declarationText(payload.files[path], `provider types files.${path}`);

    const actualHash = createHash("sha256")
        .update(canonicalContent(payload.indexFragments, payload.files))
        .digest("hex");
    if (actualHash !== payload.hash) {
        fail(`provider types artifact hash mismatch: expected ${payload.hash}, calculated ${actualHash}`);
    }

    return payload;
}

function artifactMetadata(payload) {
    return `// oidc-provider types artifact ${
        JSON.stringify(payload.providerVersion)
    }; schema ${payload.schemaVersion}; sha256 ${payload.hash}`;
}

function replaceRegion(source, fragment, { start, end, legacy, declaration }, label) {
    if (declaration && [...source.matchAll(declaration)].length !== 1) {
        fail(`index.d.ts must contain exactly one ${label} declaration`);
    }
    if (fragment.includes(start) || fragment.includes(end)) {
        fail(`provider ${label} fragment contains a generated-region marker`);
    }
    if (legacy && !source.includes(start) && !source.includes(end)) {
        const matches = [...source.matchAll(legacy)];
        if (matches.length !== 1) fail(`index.d.ts must contain exactly one unambiguous legacy ${label} declaration`);
        const match = matches[0];
        const normalized = fragment.replace(/^\n+|\n+$/g, "");
        return `${source.slice(0, match.index)}${start}\n${normalized}\n${end}${
            source.slice(match.index + match[0].length)
        }`;
    }
    const startIndex = source.indexOf(start);
    const endIndex = source.indexOf(end);
    if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
        fail(`index.d.ts does not contain the generated ${label} region`);
    }
    if (
        source.indexOf(start, startIndex + start.length) !== -1
        || source.indexOf(end, endIndex + end.length) !== -1
    ) {
        fail(`index.d.ts must contain exactly one generated ${label} region`);
    }
    if (fragment.includes(start) || fragment.includes(end)) {
        fail(`provider ${label} fragment contains a generated-region marker`);
    }

    const normalized = fragment.replace(/^\n+|\n+$/g, "");
    return `${source.slice(0, startIndex + start.length)}\n${normalized}\n${source.slice(endIndex)}`;
}

function formatDeclaration(source, packageDirectory, declarationPath) {
    const repositoryDirectory = resolve(packageDirectory, "..", "..");
    const executable = dprintExecutable(repositoryDirectory);
    const result = spawnSync(process.execPath, [executable, "fmt", "--stdin", basename(declarationPath)], {
        cwd: repositoryDirectory,
        encoding: "utf8",
        input: source,
        maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error) {
        fail(
            `could not run DefinitelyTyped's dprint executable at ${executable}: ${result.error.message}. Install the repository dependencies first`,
        );
    }
    if (result.status !== 0) {
        if (result.stderr) process.stderr.write(result.stderr);
        fail(`dprint exited with status ${result.status}`);
    }
    return result.stdout;
}

function generateArtifact(providerDirectory) {
    const result = spawnSync(process.execPath, ["docs/update-configuration.js", "--types-json"], {
        cwd: providerDirectory,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error) {
        fail(`could not run the provider types generator: ${result.error.message}`);
    }
    if (result.status !== 0) {
        if (result.stderr) process.stderr.write(result.stderr);
        fail(`provider types generator exited with status ${result.status}`);
    }

    try {
        return JSON.parse(result.stdout);
    } catch (error) {
        fail(`provider types generator returned invalid JSON: ${error.message}`);
    }
}

function renderedHash(outputs) {
    return createHash("sha256").update(JSON.stringify(Object.fromEntries(outputs))).digest("hex");
}

function renderedOutputs(outputs, packageDirectory) {
    return new Map([...outputs].map(([path, source]) => [
        path,
        formatDeclaration(
            path === "index.d.ts" ? source.replace(PROVENANCE_PATTERN, "") : source,
            packageDirectory,
            resolve(packageDirectory, path),
        ),
    ]));
}

function readOptional(path) {
    return existsSync(path) ? readFileSync(path, "utf8") : "";
}

function safeOutput(packageDirectory, path) {
    const normalized = path.split(sep).join("/");
    if (!["index.d.ts", "package.json", ...FILE_PATHS].includes(normalized)) {
        fail(`unmanaged output path: ${path}`);
    }
    const target = resolve(packageDirectory, path);
    for (let current = target; current !== packageDirectory; current = dirname(current)) {
        if (lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink()) {
            fail(`managed output must not contain a symbolic link: ${path}`);
        }
    }
    return target;
}

const parsed = parseArguments(process.argv.slice(2));
const { artifactPath, mode, providerDirectory } = parsed;
const packageDirectory = realpathSync(parsed.packageDirectory);
const indexPath = safeOutput(packageDirectory, "index.d.ts");
const packagePath = safeOutput(packageDirectory, "package.json");
for (const path of FILE_PATHS) safeOutput(packageDirectory, path);
const typesPackage = readJson(packagePath, "@types package.json");

if (typesPackage.name !== "@types/oidc-provider") {
    fail(`expected @types/oidc-provider, found ${JSON.stringify(typesPackage.name)}`);
}

let artifactPayload;
let expectedProviderVersion;
if (artifactPath === undefined) {
    const providerPackage = readJson(resolve(providerDirectory, "package.json"), "provider package.json");
    if (providerPackage.name !== "oidc-provider") {
        fail(`expected oidc-provider, found ${JSON.stringify(providerPackage.name)}`);
    }
    expectedProviderVersion = providerPackage.version;
    artifactPayload = generateArtifact(providerDirectory);
} else {
    artifactPayload = readJson(artifactPath, "provider types artifact");
}
const artifact = validateArtifact(artifactPayload, expectedProviderVersion);

const typesLine = versionLine(typesPackage.version, "@types/oidc-provider");
const providerLine = versionLine(artifact.providerVersion, "oidc-provider");
const lineComparison = compareVersionLines(providerLine, typesLine);
if (mode === "check" && lineComparison !== 0) {
    fail(
        `version mismatch: @types/oidc-provider is ${typesLine.major}.${typesLine.minor}.x but oidc-provider is ${providerLine.major}.${providerLine.minor}.x`,
    );
}

const currentIndex = readFileSync(indexPath, "utf8");
let generatedIndex = currentIndex;
for (const name of FRAGMENT_NAMES) {
    const fragment = name === "contracts"
        ? `${artifactMetadata(artifact)}\n${artifact.indexFragments[name]}`
        : artifact.indexFragments[name];
    generatedIndex = replaceRegion(generatedIndex, fragment, REGIONS[name], name);
}
const candidateOutputs = new Map([
    ["index.d.ts", formatDeclaration(generatedIndex, packageDirectory, indexPath)],
    ...FILE_PATHS.map((path) => [path, artifact.files[path]]),
]);
const exactOutputs = new Map(
    [...candidateOutputs].map(([path, contents]) => [resolve(packageDirectory, path), contents]),
);
const currentOutputs = new Map(
    [...candidateOutputs].map(([path]) => [path, readOptional(resolve(packageDirectory, path))]),
);
const currentRendered = renderedOutputs(currentOutputs, packageDirectory);
const candidateRendered = renderedOutputs(candidateOutputs, packageDirectory);
const renderedChanges = [...candidateRendered]
    .filter(([path, contents]) => currentRendered.get(path) !== contents)
    .map(([path]) => path);
const declarationChanges = renderedChanges.filter((path) => path === "index.d.ts" || path.endsWith(".d.ts"));
const testChanges = renderedChanges.filter((path) => !declarationChanges.includes(path));
const reasons = [];
if (declarationChanges.length) reasons.push("declarations");
if (testChanges.length) reasons.push("tests");
if (providerLine.major > typesLine.major) reasons.push("major-version");

const olderTrackedLine = lineComparison < 0;
const updateRequired = !olderTrackedLine && reasons.length > 0;
const warning = olderTrackedLine
    ? `oidc-provider ${artifact.providerVersion} is older than the tracked @types/oidc-provider ${typesLine.major}.${typesLine.minor}.x line; skipping`
    : undefined;

if (updateRequired) {
    const candidateVersion = targetTypesVersion(providerLine);
    if (typesPackage.version !== candidateVersion) {
        exactOutputs.set(packagePath, `${JSON.stringify({ ...typesPackage, version: candidateVersion }, null, 4)}\n`);
    }
}
const changedFiles = updateRequired
    ? [...exactOutputs]
        .filter(([path, contents]) => readOptional(path) !== contents)
        .map(([path]) => relative(packageDirectory, path).split(sep).join("/"))
    : [];

if (mode === "status") {
    const status = {
        schemaVersion: STATUS_SCHEMA_VERSION,
        updateRequired,
        reasons: updateRequired ? reasons : [],
        providerVersion: artifact.providerVersion,
        typesVersion: typesPackage.version,
        currentHash: renderedHash(currentRendered),
        candidateHash: renderedHash(candidateRendered),
        changedFiles,
    };
    if (warning !== undefined) status.warning = warning;
    process.stdout.write(`${JSON.stringify(status)}\n`);
} else if (olderTrackedLine) {
    console.warn(`update-types: ${warning}`);
} else {
    if (mode === "update" && !updateRequired) {
        console.log("No declaration update is required for this oidc-provider release.");
        process.exit(0);
    }

    const changed = [...exactOutputs].filter(([path, contents]) => readOptional(path) !== contents);
    if (!changed.length) {
        console.log("oidc-provider declaration mirrors are up to date.");
    } else if (mode === "check") {
        fail(
            `declaration mirrors are not up to date: ${
                changed.map(([path]) => relative(packageDirectory, path).split(sep).join("/")).join(", ")
            }`,
        );
    } else {
        for (const [path] of changed) safeOutput(packageDirectory, relative(packageDirectory, path));
        for (const [path, contents] of changed) {
            mkdirSync(dirname(path), { recursive: true });
            writeFileSync(path, contents);
        }
        console.log(
            `Updated oidc-provider declaration mirrors: ${
                changed.map(([path]) => relative(packageDirectory, path).split(sep).join("/")).join(", ")
            }.`,
        );
    }
}
