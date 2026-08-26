import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { parse } from '@babel/parser';

import events from '../types/events.js';

export const TYPES_SCHEMA_VERSION = 1;

const parserOptions = {
  plugins: ['typescript'],
  sourceType: 'module',
};

const configurationUrl = new URL('../types/configuration.d.ts', import.meta.url);
const providerUrl = new URL('../types/provider.d.ts', import.meta.url);
const relatedUrl = new URL('../types/related.d.ts', import.meta.url);
const grantsUrl = new URL('../types/lib/helpers/grants.d.ts', import.meta.url);

function visit(value, callback, ancestors = []) {
  if (Array.isArray(value)) {
    for (const entry of value) visit(entry, callback, ancestors);
    return;
  }

  if (!value || typeof value !== 'object') return;

  if (typeof value.type === 'string') {
    callback(value, ancestors.at(-1), ancestors);
    ancestors = [...ancestors, value];
  }

  for (const [key, child] of Object.entries(value)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') {
      continue;
    }
    visit(child, callback, ancestors);
  }
}

function propertyName(node) {
  switch (node.key.type) {
    case 'Identifier':
    case 'StringLiteral':
    case 'NumericLiteral':
      return String(node.key.name ?? node.key.value);
    default:
      return undefined;
  }
}

function normalizedType(source) {
  return source.replaceAll(/\s+/g, ' ').trim();
}

function typeSource(source, node) {
  if (node.type === 'TSUnionType') {
    const members = node.types.filter((member) => member.type !== 'TSUndefinedKeyword');
    if (members.length !== node.types.length) {
      if (members.length === 1) return typeSource(source, members[0]);
      return members.map((member) => {
        const rendered = typeSource(source, member);
        return member.type === 'TSFunctionType' || member.type === 'TSConstructorType'
          ? `(${rendered})`
          : rendered;
      }).join(' | ');
    }
  }

  const lines = source
    .slice(node.start, node.end)
    .replaceAll(/^[ \t]*\/\/ @configuration-(?:path|docs|dynamic) [^\s]+[ \t]*\n?/gm, '')
    .trim()
    .split('\n');
  if (lines.length > 1) {
    const baseIndentation = /^[ \t]*/.exec(lines.at(-1))[0].length;
    for (let index = 1; index < lines.length; index += 1) {
      lines[index] = lines[index].slice(Math.min(baseIndentation, /^[ \t]*/.exec(lines[index])[0].length));
    }
  }
  return lines.join('\n');
}

function callableTypes(source, node, aliases, seen = new Set()) {
  switch (node.type) {
    case 'TSFunctionType':
      return [typeSource(source, node)];
    case 'TSParenthesizedType':
      return callableTypes(source, node.typeAnnotation, aliases, seen);
    case 'TSUnionType':
    case 'TSIntersectionType':
      return node.types.flatMap((member) => callableTypes(source, member, aliases, seen));
    case 'TSTypeReference': {
      if (node.typeName.type !== 'Identifier' || seen.has(node.typeName.name)) return [];
      const alias = aliases.get(node.typeName.name);
      if (!alias) return [];
      seen.add(node.typeName.name);
      const result = callableTypes(source, alias, aliases, seen);
      seen.delete(node.typeName.name);
      return result;
    }
    default:
      return [];
  }
}

function containsCallable(node, aliases, inspectObject = true, seen = new Set()) {
  switch (node.type) {
    case 'TSFunctionType':
      return true;
    case 'TSParenthesizedType':
      return containsCallable(node.typeAnnotation, aliases, inspectObject, seen);
    case 'TSUnionType':
    case 'TSIntersectionType':
      return node.types.some((member) => containsCallable(member, aliases, inspectObject, seen));
    case 'TSTypeReference': {
      if (node.typeName.type !== 'Identifier' || seen.has(node.typeName.name)) return false;
      const alias = aliases.get(node.typeName.name);
      if (!alias) return false;
      seen.add(node.typeName.name);
      const result = containsCallable(alias, aliases, inspectObject, seen);
      seen.delete(node.typeName.name);
      return result;
    }
    case 'TSTypeLiteral':
      return inspectObject && node.members.some((member) => (
        member.type === 'TSPropertySignature'
        && member.typeAnnotation?.typeAnnotation
        && containsCallable(member.typeAnnotation.typeAnnotation, aliases, false, seen)
      ));
    default:
      return false;
  }
}

function markerRecords(source) {
  return Array.from(
    source.matchAll(/^[ \t]*\/\/ @(configuration-path|configuration-docs|configuration-dynamic) ([^\s]+)[ \t]*$/gm),
    (match) => ({
      kind: match[1],
      path: match[2],
      start: match.index,
      end: match.index + match[0].length,
    }),
  );
}

function withoutTemplateHeader(source) {
  return source.replace(/^\/\*\*[\s\S]*?\*\/\n+/, '');
}

export function readConfigurationContract(
  source = readFileSync(configurationUrl, 'utf8'),
) {
  source = source.replaceAll('\r\n', '\n');
  const ast = parse(source, parserOptions);
  const properties = [];
  const aliases = new Map();
  const ownerDependencies = new Map();
  const unionOwners = new Set();

  visit(ast.program, (node, _parent, ancestors) => {
    if (node.type === 'TSPropertySignature' && node.typeAnnotation?.typeAnnotation) {
      const owner = ancestors.findLast((ancestor) => (
        ancestor.type === 'TSInterfaceDeclaration' || ancestor.type === 'TSTypeAliasDeclaration'
      ));
      properties.push({ node, owner: owner?.id.name });
    } else if (node.type === 'TSTypeAliasDeclaration') {
      aliases.set(node.id.name, node.typeAnnotation);
    }
  });
  properties.sort((left, right) => left.node.start - right.node.start);

  visit(ast.program, (node) => {
    if (node.type === 'TSInterfaceDeclaration') {
      ownerDependencies.set(node.id.name, new Set((node.extends ?? [])
        .filter(({ expression }) => expression.type === 'Identifier')
        .map(({ expression }) => expression.name)));
    } else if (node.type === 'TSTypeAliasDeclaration') {
      const dependencies = new Set();
      let containsUnion = false;
      visit(node.typeAnnotation, (child) => {
        if (child.type === 'TSUnionType') containsUnion = true;
        if (child.type === 'TSTypeReference' && child.typeName.type === 'Identifier') {
          dependencies.add(child.typeName.name);
        }
      });
      ownerDependencies.set(node.id.name, dependencies);
      if (containsUnion) unionOwners.add(node.id.name);
    }
  });

  function ownerDependsOn(owner, expected) {
    const seen = new Set();
    const pending = [owner];
    while (pending.length) {
      const candidate = pending.pop();
      if (!candidate || seen.has(candidate)) continue;
      seen.add(candidate);
      if (candidate === expected) return true;
      pending.push(...(ownerDependencies.get(candidate) ?? []));
    }
    return false;
  }

  const paths = new Map();
  const dynamic = new Set();
  const documentationOccurrences = [];
  const documentedProperties = new Set();

  for (const marker of markerRecords(source)) {
    const propertyRecord = properties.find(({ node }) => node.start >= marker.end);
    if (!propertyRecord) {
      throw new TypeError(`${marker.kind} marker for ${marker.path} is not followed by a property`);
    }
    const { node: property, owner } = propertyRecord;

    const gap = source.slice(marker.end, property.start);
    if (gap.replaceAll(/^[ \t]*\/\/ @configuration-(?:path|docs|dynamic) [^\s]+[ \t]*$/gm, '').trim()) {
      throw new TypeError(`${marker.kind} marker for ${marker.path} is not adjacent to a property`);
    }

    const expectedName = marker.path.split('.').at(-1);
    const actualName = propertyName(property);
    if (actualName !== expectedName) {
      throw new TypeError(`${marker.kind} marker for ${marker.path} annotates ${actualName}`);
    }

    if (marker.kind !== 'configuration-dynamic') {
      if (documentedProperties.has(property)) {
        throw new TypeError(
          `property ${actualName} has multiple configuration documentation markers`,
        );
      }
      documentedProperties.add(property);
    }

    if (marker.kind === 'configuration-dynamic') {
      if (dynamic.has(marker.path)) {
        throw new TypeError(`duplicate dynamic configuration namespace ${marker.path}`);
      }
      dynamic.add(marker.path);
      continue;
    }

    if (marker.kind === 'configuration-docs') {
      documentationOccurrences.push({ node: property, owner, path: marker.path });
      continue;
    }

    const annotation = property.typeAnnotation.typeAnnotation;
    const entry = {
      node: property,
      optional: Boolean(property.optional),
      owner,
      type: typeSource(source, annotation),
      typeNode: annotation,
    };
    const entries = paths.get(marker.path) ?? [];
    entries.push(entry);
    paths.set(marker.path, entries);
  }

  const types = new Map();
  const callbacks = new Map();
  const callablePaths = new Set();

  function ownersRelated(owner, expected) {
    return owner === expected
      || ownerDependsOn(owner, expected)
      || [...unionOwners].some((unionOwner) => (
        ownerDependsOn(unionOwner, expected) && ownerDependsOn(unionOwner, owner)
      ));
  }

  for (const [path, entries] of paths) {
    const [canonical, ...refinements] = entries;
    for (const refinement of refinements) {
      if (!ownersRelated(refinement.owner, canonical.owner)) {
        throw new TypeError(
          `configuration path ${path} is repeated by unrelated declarations ${canonical.owner} and ${refinement.owner}`,
        );
      }

      if (!canonical.optional && refinement.optional) {
        throw new TypeError(
          `configuration path ${path} makes a required property optional in ${refinement.owner}`,
        );
      }

      const canonicalType = normalizedType(canonical.type);
      const refinementType = normalizedType(refinement.type);
      const booleanLiteralNarrowing = canonicalType === 'boolean'
        && (refinementType === 'true' || refinementType === 'false');
      if (canonicalType !== refinementType && !booleanLiteralNarrowing) {
        throw new TypeError(
          `configuration path ${path} widens or changes its type in ${refinement.owner}: ${refinement.type}`,
        );
      }
    }

    types.set(path, canonical.type);
    if (entries.some((entry) => containsCallable(entry.typeNode, aliases))) {
      callablePaths.add(path);
    }

    const declaredCallbacks = new Map(entries.flatMap((entry) => (
      callableTypes(source, entry.typeNode, aliases)
        .map((type) => [normalizedType(type), type])
    )));
    if (declaredCallbacks.size === 1) {
      callbacks.set(path, declaredCallbacks.values().next().value);
    } else if (declaredCallbacks.size > 1) {
      throw new TypeError(
        `configuration path ${path} has multiple callable declarations: ${[...declaredCallbacks.values()].join(', ')}`,
      );
    }
  }

  for (const occurrence of documentationOccurrences) {
    const entries = paths.get(occurrence.path);
    if (!entries) {
      throw new TypeError(
        `configuration-docs marker for ${occurrence.path} has no declared configuration path`,
      );
    }

    const canonical = entries[0];
    if (!ownersRelated(occurrence.owner, canonical.owner)) {
      throw new TypeError(
        `configuration docs for ${occurrence.path} are repeated by unrelated declarations ${canonical.owner} and ${occurrence.owner}`,
      );
    }
  }

  for (const path of dynamic) {
    if (!paths.has(path)) {
      throw new TypeError(`dynamic configuration namespace ${path} has no declared property`);
    }
  }

  return { callablePaths, callbacks, dynamic, paths, source, types };
}

export function renderConfigurationContract(source, documentationByPath, renderDocumentation) {
  return withoutTemplateHeader(source)
    .replace(
      /^([ \t]*)\/\/ @configuration-(?:path|docs) ([^\s]+)[ \t]*$/gm,
      (_match, indentation, path) => {
        const documentation = documentationByPath.get(path);
        if (!documentation) {
          throw new TypeError(`missing configuration documentation for ${path}`);
        }
        return renderDocumentation(documentation, indentation);
      },
    )
    .replace(/^[ \t]*\/\/ @configuration-dynamic [^\s]+[ \t]*\n?/gm, '');
}

function prose(value, label, path, sourceBase) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`configuration documentation for ${path} has an invalid ${label}`);
  }
  return value
    .replaceAll('\r\n', '\n')
    .trim()
    .replaceAll('*/', '*\\/')
    .replaceAll(/\]\(\/(?!\/)/g, `](${sourceBase}/`);
}

function cleanedDefaultWarning(value, path, sourceBase) {
  const lines = prose(value, 'default warning', path, sourceBase).split('\n');
  if (lines[0] === '> [!IMPORTANT]') lines.shift();
  const warning = lines.map((line) => line.replace(/^> ?/, '')).join('\n').trim();
  return `**Important:**\n\n${warning}`;
}

function wrappedMarkdownLines(value, width) {
  const result = [];
  for (const sourceLine of value.split('\n')) {
    if (!sourceLine.trim()) {
      result.push('');
      continue;
    }

    const match = /^(\s*(?:[-*+] |\d+\. |@see )?)(.*)$/.exec(sourceLine);
    const prefix = match[1];
    const continuation = ' '.repeat(prefix.length);
    const tokens = match[2].match(/`[^`]*`|\[[^\]]+\]\([^)]+\)|\S+/g) ?? [];
    let line = prefix;

    for (const token of tokens) {
      const separator = line === prefix || /^[,.;:!?)]/.test(token) ? '' : ' ';
      if (line.length > prefix.length && line.length + separator.length + token.length > width) {
        result.push(line);
        line = `${continuation}${token}`;
      } else {
        line += `${separator}${token}`;
      }
    }
    result.push(line);
  }
  return result;
}

export function renderConfigurationJSDoc(entry, indentation, sourceBase) {
  const sections = [];

  if (entry.title !== undefined) sections.push(prose(entry.title, 'title', entry.path, sourceBase));
  if (entry.experimental === true) sections.push('This is an experimental feature.');
  if (entry.defaultWarning !== undefined) {
    sections.push(cleanedDefaultWarning(entry.defaultWarning, entry.path, sourceBase));
  }
  if (entry.description !== undefined) {
    sections.push(prose(entry.description, 'description', entry.path, sourceBase));
  }

  if (entry.recommendations !== undefined) {
    if (!Array.isArray(entry.recommendations)) {
      throw new TypeError(`configuration documentation for ${entry.path} has invalid recommendations`);
    }
    for (const recommendation of entry.recommendations) {
      sections.push(`**Recommendation:** ${prose(recommendation, 'recommendation', entry.path, sourceBase)}`);
    }
  }

  if (entry.see !== undefined) {
    if (!Array.isArray(entry.see)) {
      throw new TypeError(`configuration documentation for ${entry.path} has invalid see references`);
    }
    for (const reference of entry.see) {
      sections.push(`@see ${prose(reference, 'see reference', entry.path, sourceBase)}`);
    }
  }

  const lines = ['/**'];
  const width = Math.max(40, 120 - indentation.length - 3);
  for (const [sectionIndex, section] of sections.entries()) {
    if (sectionIndex) lines.push(' *');
    for (const line of wrappedMarkdownLines(section, width)) lines.push(line ? ` * ${line}` : ' *');
  }
  lines.push(' */');
  return lines.map((line) => `${indentation}${line}`).join('\n');
}

function listenerType(event) {
  return `(${event.arguments.map(([name, type]) => `${name}: ${type}`).join(', ')}) => void`;
}

function eventMapInterface() {
  const mapped = events.filter(({ mapped }) => mapped);
  if (!mapped.length) return '';

  const lines = ['interface ProviderAdditionalEventMap {'];
  for (const event of mapped) {
    lines.push(`    ${JSON.stringify(event.name)}: ${listenerType(event)};`);
  }
  lines.push('}');
  return lines.join('\n');
}

function eventListenerOverloads() {
  const methods = ['addListener', 'on', 'once', 'prependListener', 'prependOnceListener'];
  const explicit = events.filter(({ mapped }) => !mapped);
  const lines = ['// tslint:disable:unified-signatures'];

  for (const method of methods) {
    for (const event of explicit) {
      lines.push(
        `${method}(event: ${JSON.stringify(event.name)}, listener: ${listenerType(event)}): this;`,
      );
    }
    lines.push(
      `${method}<Event extends keyof ProviderAdditionalEventMap>(`,
      '    event: Event,',
      '    listener: ProviderAdditionalEventMap[Event],',
      '): this;',
    );
  }

  lines.push('// tslint:enable:unified-signatures');
  return lines.join('\n');
}

export function renderProviderContract() {
  const source = readFileSync(providerUrl, 'utf8').replaceAll('\r\n', '\n');
  const begin = '    // @generate-event-listener-overloads begin';
  const end = '    // @generate-event-listener-overloads end';
  const beginIndex = source.indexOf(begin);
  const endIndex = source.indexOf(end);
  if (beginIndex === -1 || endIndex === -1 || endIndex <= beginIndex) {
    throw new TypeError('Provider contract must contain one event-listener overload directive');
  }
  if (source.indexOf(begin, beginIndex + begin.length) !== -1 || source.indexOf(end, endIndex + end.length) !== -1) {
    throw new TypeError('Provider contract contains duplicate event-listener overload directives');
  }

  const directiveEnd = source.indexOf('\n', endIndex);
  const overloads = eventListenerOverloads().split('\n').map((line) => `    ${line}`).join('\n');
  const rendered = `${source.slice(0, beginIndex)}${overloads}${source.slice(directiveEnd)}`;
  const ast = parse(rendered, parserOptions);
  const wrapper = ast.program.body
    .map((node) => node.type === 'ExportNamedDeclaration' ? node.declaration : node)
    .find((node) => node?.type === 'ClassDeclaration' && node.id?.name === 'ProviderExtensibilityContract');
  if (!wrapper) throw new TypeError('Provider contract wrapper class was not found');

  const body = rendered.slice(wrapper.body.start + 1, wrapper.body.end - 1).trim();
  return body.split('\n').map((line) => line.startsWith('    ') ? line.slice(4) : line).join('\n');
}

export function readRelatedContract() {
  const source = withoutTemplateHeader(
    readFileSync(relatedUrl, 'utf8').replaceAll('\r\n', '\n'),
  ).trim();
  parse(source, parserOptions);
  return source;
}

export function readGrantHelperContract() {
  const source = readFileSync(grantsUrl, 'utf8').replaceAll('\r\n', '\n');
  parse(source, parserOptions);
  return source;
}

export function renderEventMapContract() {
  return eventMapInterface();
}

export function renderEventsDocumentation() {
  const rows = events.map((event) => [
    `\`${event.name}\``,
    `\`(${event.arguments.map(([name, , documentationName]) => documentationName ?? name).join(', ')})\``,
    `... ${event.description}`,
  ]);
  const headers = ['event name', 'event handler function parameters', 'Emitted ..'];
  const widths = headers.map((header, index) => Math.max(
    header.length,
    ...rows.map((row) => row[index].length),
  ));
  const row = (cells) => `| ${cells.map((cell, index) => cell.padEnd(widths[index])).join(' | ')} |`;
  const separator = row(widths.map((width) => '-'.repeat(width)));
  const table = [row(headers), separator, ...rows.map(row)].join('\n');

  return `# Events

Your oidc-provider instance is an event emitter, in the event handlers \`this\` is always the
Provider instance. In events where
\`ctx\` (request context) is passed to the listener \`ctx.oidc\`
[OIDCContext](/lib/helpers/oidc_context.js) holds additional details like recognized parameters,
loaded client or session.

Handled errors that wrap an underlying failure may expose it through the standard \`cause\`
property. This is intended for diagnostics in error listeners and is not included in protocol
responses.

${table}

External type definitions are available via [DefinitelyTyped](https://npmjs.com/package/@types/oidc-provider).
`;
}

export function validateEvents() {
  const names = new Set();
  for (const [index, event] of events.entries()) {
    if (!event || typeof event !== 'object') throw new TypeError(`event ${index} must be an object`);
    if (typeof event.name !== 'string' || !event.name) throw new TypeError(`event ${index} has an invalid name`);
    if (names.has(event.name)) throw new TypeError(`duplicate event ${event.name}`);
    names.add(event.name);
    if (!Array.isArray(event.arguments)) throw new TypeError(`event ${event.name} has invalid arguments`);
    if (typeof event.description !== 'string' || !event.description) {
      throw new TypeError(`event ${event.name} has an invalid description`);
    }
    if (typeof event.mapped !== 'boolean') throw new TypeError(`event ${event.name} has an invalid mapped flag`);
  }
  return names;
}

export function contentHash(payload) {
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}
