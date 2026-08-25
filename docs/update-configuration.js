import { createReadStream, readFileSync, writeFileSync } from 'node:fs';
import { createInterface as readline } from 'node:readline';
import { inspect } from 'node:util';

import { parse, parseExpression } from '@babel/parser';
import get from 'lodash/get.js';
import words from 'lodash/words.js';

import { defaults } from '../lib/helpers/defaults.js';
import consent from '../lib/helpers/interaction_policy/prompts/consent.js';
import login from '../lib/helpers/interaction_policy/prompts/login.js';

// Usage:
//   node docs/update-configuration.js
//     Regenerates the configuration reference in docs/README.md.
//   node docs/update-configuration.js --configuration-json
//     Prints configuration documentation and declared types as JSON without
//     modifying docs/README.md. Paths are resolved relative to this script.
const [mode, ...extraArguments] = process.argv.slice(2);
const emitConfigurationJson = mode === '--configuration-json';

const parserOptions = { plugins: ['typescript'] };

function publicName(block) {
  const name = block.split('.').at(-1);
  return /^[A-Za-z_$][\w$]*$/.test(name) ? name : 'defaultValue';
}

function parsedFunction(source) {
  try {
    return { node: parseExpression(`(${source})`, parserOptions), offset: 1 };
  } catch (functionError) {
    try {
      const expression = parseExpression(`({${source}})`, parserOptions);
      const [node] = expression.properties;
      if (expression.properties.length !== 1 || node.type !== 'ObjectMethod') {
        throw functionError;
      }
      return { node, offset: 2 };
    } catch {
      throw functionError;
    }
  }
}

function normalizeFunctionExpression(source, block, placeholder = false) {
  const { node, offset } = parsedFunction(source);
  if (!['FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod'].includes(node.type)) {
    throw new TypeError(`unsupported function source for ${block}`);
  }
  if (node.generator) {
    throw new TypeError(`generator functions are not supported as configuration defaults (${block})`);
  }

  const params = node.params.length
    ? source.slice(node.params[0].start - offset, node.params.at(-1).end - offset)
    : '';
  let body;
  if (placeholder) {
    body = '{ /* implementation required */ }';
  } else if (node.body.type === 'BlockStatement') {
    body = source.slice(node.body.start - offset, node.body.end - offset);
  } else {
    const expression = source.slice(node.body.start - offset, node.body.end - offset);
    body = `{ return ${expression}; }`;
  }

  return `${node.async ? 'async ' : ''}function ${publicName(block)}(${params}) ${body}`;
}

function stripLeadingParameterComments(source) {
  const { node, offset } = parsedFunction(source);
  const start = node.body.start - offset + 1;
  const end = (node.body.body[0]?.start ?? node.body.end - 1) - offset;
  const prefix = source.slice(start, end);

  if (!prefix.includes('// @param')) {
    return source;
  }

  let removing = false;
  let stripped = prefix.split('\n').map((line) => {
    if (/^\s*\/\/ @param\b/.test(line)) {
      removing = true;
      return '';
    }
    if (removing && /^\s*\/\//.test(line)) {
      return '';
    }
    removing = false;
    return line;
  }).join('\n');

  if (!stripped.trim()) {
    const indentation = prefix.match(/\n([ \t]*)$/)?.[1] || '  ';
    stripped = node.body.body.length ? `\n${indentation}` : '';
  }

  return `${source.slice(0, start)}${stripped}${source.slice(end)}`;
}

function isUnconditionalPlaceholder(value) {
  const source = String(value);
  return source.includes('mustChange(')
    && /\bthrow\b/.test(source)
    && !/(?:^|\n)\s*return\b/.test(source);
}

function functionSource(value, block) {
  if (isUnconditionalPlaceholder(value)) {
    return normalizeFunctionExpression(String(value).trim(), block, true);
  }

  const implementation = value;
  let fixIndent;
  let mute = false;

  const source = String(implementation).trim().split('\n').map((line, index) => {
    if (index === 1) {
      line.match(/^(\s+)\S+/);
      fixIndent = RegExp.$1.length - 2;
    }
    if (line.includes('shouldChange')) return undefined;
    if (line.includes('mustChange')) return undefined;
    if (line.startsWith(' ')) {
      line = line.replace(new RegExp(`^( {0,${fixIndent}})`), '');
    }
    line = line.replace(/ \/\/ TODO.+/, '');
    line = line.replace(/ class="[ \-\w]+ ?"/, '');
    if (line.includes('<meta ')) {
      return undefined;
    }
    if (line.includes('<style>')) {
      mute = true;
      line.match(/^(\s+)/);
      return `${' '.repeat(Math.max(fixIndent, RegExp.$1.length))}<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>`;
    }
    if (line.includes('</style>')) {
      mute = false;
      return undefined;
    }
    if (mute) return undefined;
    return line;
  }).filter(Boolean).join('\n');

  return stripLeadingParameterComments(normalizeFunctionExpression(source, block));
}

for (const [name, value] of Object.entries(defaults.ttl)) {
  if (typeof value === 'function') {
    value[inspect.custom] = () => functionSource(value, `ttl.${name}`);
  }
}

defaults.interactions.policy[inspect.custom] = () => `[
/* LOGIN PROMPT */
${login.toString().replace('() => new Prompt', 'new Prompt')},

/* CONSENT PROMPT */
${consent.toString().replace('() => new Prompt', 'new Prompt')}
]`;

function capitalizeSentences(copy) {
  return copy.replace(/\. [a-z]/g, (match) => `. ${match.slice(-1).toUpperCase()}`);
}

class Block {
  write(buffer) {
    if (!this[this.active]) {
      this[this.active] = [buffer];
    } else {
      // Strip leading * characters
      while (buffer.length && buffer[0] === 0x2A) {
        buffer = buffer.slice(1);
      }

      if (this.active === 'type') {
        if (buffer[0] === 0x20) {
          buffer = buffer.slice(1);
        }
        this[this.active].push(buffer);
        return;
      }

      // Count leading spaces
      let spaceCount = 0;
      while (buffer.length > spaceCount && buffer[spaceCount] === 0x20) {
        spaceCount += 1;
      }

      // Check if this is a list item (- or 1. after spaces)
      const afterSpaces = buffer.slice(spaceCount).toString();
      const isListItem = afterSpaces.startsWith('-') || /^\d+\./.test(afterSpaces);

      if (isListItem) {
        // Track base indentation per section to preserve sub-list indentation
        const bliKey = `_baseListIndent_${this.active}`;
        if (this[bliKey] === undefined) {
          this[bliKey] = spaceCount;
        }
        const relativeIndent = Math.max(0, spaceCount - this[bliKey]);
        buffer = Buffer.from(`${' '.repeat(relativeIndent)}${afterSpaces}`);
      } else {
        // Strip all leading spaces for non-list content
        buffer = buffer.slice(spaceCount);
      }

      if (buffer.indexOf('@indent@') === 0) {
        buffer = buffer.slice(10);
      }

      const bufStr = buffer.toString();
      const trimmedBufStr = bufStr.trimStart();
      if (trimmedBufStr.startsWith('-') || /^\d+\./.test(trimmedBufStr) || bufStr.includes('```') || trimmedBufStr.startsWith('|')) {
        const last = this[this.active].pop();
        if (last.toString().endsWith('\n')) {
          this[this.active].push(last);
        } else {
          this[this.active].push(Buffer.concat([last, Buffer.from('\n')]));
        }
      }

      if (buffer.length) {
        this[this.active].push(buffer);
      } else if (this.active === 'description' || this.active.startsWith('recommendation')) {
        this[this.active].push(Buffer.from('\n\n'));
      }
    }
  }
}

const props = [
  'description',
  'title',
  'type',
  'recommendation',
  'example',
  'see',
  '@nodefault',
  '@skip',
  '@important',
];

let mid = Buffer.from('');

function append(what) {
  mid = Buffer.concat([mid, Buffer.from(what)]);
}

function smartJoin(parts) {
  let result = '';
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].toString();
    if (i > 0 && !result.endsWith('\n')) {
      result += ' ';
    }
    result += part;
  }
  return result;
}

function normalizeMarkdown(value) {
  return value.replace(/[ \t]+$/gm, '').trim();
}

function expand(what, language = 'js') {
  what = `\`\`\`${language}\n${what}\n\`\`\`\n`;

  append('\n_**default value**_:\n');
  return what;
}

function typeSource(section) {
  return section.type?.map((part) => part.toString()).join('\n').trim();
}

function configurationDocumentation(blocks, orderedBlocks) {
  return orderedBlocks.map((path) => {
    const section = blocks[path];
    const value = get(defaults, path);
    const type = typeSource(blocks[path]);
    const title = section.title && normalizeMarkdown(smartJoin(section.title));
    const description = section.description
      && normalizeMarkdown(capitalizeSentences(smartJoin(section.description)));
    const see = section.see
      ?.map((part) => normalizeMarkdown(part.toString()))
      .filter(Boolean);
    const recommendations = Object.keys(section)
      .filter((property) => property.startsWith('recommendation'))
      .map((property) => normalizeMarkdown(smartJoin(section[property])))
      .filter(Boolean);
    const markers = collectChangeMarkers(value)
      .filter((marker) => appliesToBlock(marker, path, blocks));
    const mustConfigure = Array.from(new Set(
      markers.filter(({ change }) => change === 'mustChange').map((marker) => marker.block),
    ));
    const shouldCustomize = Array.from(new Set(
      markers.filter(({ change }) => change === 'shouldChange').map((marker) => marker.block),
    ));
    const entry = { path };

    if (type) entry.type = type;
    if (title) entry.title = title;
    if (description) entry.description = description;
    if (see?.length) entry.see = see;
    if (recommendations.length) entry.recommendations = recommendations;
    if ('@important' in section) entry.important = true;
    if (typeof value === 'object' && value !== null && 'ack' in value) {
      entry.experimental = true;
    }
    if ('@nodefault' in section) entry.nodefault = true;
    const defaultWarning = changeAdmonition(value, path, blocks, false);
    if (defaultWarning) entry.defaultWarning = normalizeMarkdown(defaultWarning);
    if (mustConfigure.length || shouldCustomize.length) {
      entry.placeholders = {};
      if (mustConfigure.length) entry.placeholders.mustConfigure = mustConfigure;
      if (shouldCustomize.length) entry.placeholders.shouldCustomize = shouldCustomize;
    }

    return entry;
  });
}

function typedDefault(name, type, implementation) {
  const source = `const ${name}: ${type} = ${implementation};`;
  parse(source, { ...parserOptions, sourceType: 'module' });
  return source;
}

function parsedType(type) {
  const source = `type Callback = ${type};`;
  const [declaration] = parse(source, parserOptions).program.body;

  return { node: declaration?.typeAnnotation, source };
}

function parsedFunctionType(type, block) {
  const { node, source } = parsedType(type);

  if (node?.type !== 'TSFunctionType') {
    throw new TypeError(`callable type metadata must be a function type (${block})`);
  }

  return { node, source };
}

function sourceForNode(source, node, offset = 0) {
  return source.slice(node.start - offset, node.end - offset);
}

function typeAnnotationSource(source, parameter, block) {
  const annotation = parameter.typeAnnotation?.typeAnnotation;
  if (!annotation) {
    throw new TypeError(`missing parameter type metadata for ${block}`);
  }
  return sourceForNode(source, annotation);
}

function typedParameter(parameter, declared, implementation, offset, metadata, block) {
  const type = typeAnnotationSource(metadata, declared, block);

  switch (parameter.type) {
    case 'Identifier':
    case 'ObjectPattern':
    case 'ArrayPattern': {
      const pattern = sourceForNode(implementation, parameter, offset);
      if (declared.optional) {
        if (parameter.type !== 'Identifier') {
          throw new TypeError(`optional binding patterns are not supported (${block})`);
        }
        return `${pattern}?: ${type}`;
      }
      return `${pattern}: ${type}`;
    }
    case 'AssignmentPattern': {
      const left = sourceForNode(implementation, parameter.left, offset);
      const right = sourceForNode(implementation, parameter.right, offset);
      return `${left}: ${type} = ${right}`;
    }
    case 'RestElement':
      if (declared.type !== 'RestElement') {
        throw new TypeError(`rest parameter metadata mismatch for ${block}`);
      }
      return `${sourceForNode(implementation, parameter, offset)}: ${type}`;
    default:
      throw new TypeError(`unsupported function parameter in ${block}`);
  }
}

function declaredParameter(parameter, metadata, block) {
  if (!parameter.typeAnnotation) {
    throw new TypeError(`missing parameter type metadata for ${block}`);
  }
  return sourceForNode(metadata, parameter);
}

function returnTypeSource(metadata, returnType, asynchronous, block) {
  const node = returnType?.typeAnnotation;
  if (!node) {
    throw new TypeError(`missing return type metadata for ${block}`);
  }

  if (!asynchronous) {
    return sourceForNode(metadata, node);
  }

  if (
    node.type === 'TSTypeReference'
    && node.typeName.type === 'Identifier'
    && node.typeName.name === 'CanBePromise'
    && node.typeArguments?.params.length === 1
  ) {
    return `Promise<${sourceForNode(metadata, node.typeArguments.params[0])}>`;
  }

  if (
    node.type === 'TSTypeReference'
    && node.typeName.type === 'Identifier'
    && node.typeName.name === 'Promise'
  ) {
    return sourceForNode(metadata, node);
  }

  throw new TypeError(`async callable type must return CanBePromise<T> or Promise<T> (${block})`);
}

function typedFunctionDefault(block, type, implementation) {
  const parsedImplementation = parsedFunction(implementation);
  const { node: fn, offset } = parsedImplementation;
  const { node: declared, source: metadata } = parsedFunctionType(type, block);

  if (fn.params.length > declared.params.length) {
    throw new TypeError(`callable default has more parameters than its type metadata (${block})`);
  }

  const parameters = declared.params.map((parameter, index) => (
    fn.params[index]
      ? typedParameter(fn.params[index], parameter, implementation, offset, metadata, block)
      : declaredParameter(parameter, metadata, block)
  ));
  const body = sourceForNode(implementation, fn.body, offset);
  const returns = returnTypeSource(metadata, declared.returnType, fn.async, block);
  const signature = type.includes('\n')
    ? `(\n  ${parameters.join(',\n  ')},\n)`
    : `(${parameters.join(', ')})`;
  const source = `${fn.async ? 'async ' : ''}function ${publicName(block)}${signature}: ${returns} ${body}`;

  parse(source, { ...parserOptions, sourceType: 'module' });
  return source;
}

function collectChangeMarkers(value, seen = new Set()) {
  if (typeof value === 'function') {
    return Array.from(
      value.toString().matchAll(/\b(shouldChange|mustChange)\((?:ctx,\s*)?(['"])([^'"]+)\2/g),
      ([, change, , block]) => ({ change, block }),
    );
  }

  if (!value || typeof value !== 'object' || seen.has(value)) {
    return [];
  }

  seen.add(value);

  return Object.values(value).flatMap((entry) => collectChangeMarkers(entry, seen));
}

function rendersOwnSection(blocks, block) {
  return block in blocks && !('@skip' in blocks[block]);
}

function parentBlock(block) {
  return block.split('.').slice(0, -1).join('.');
}

function appliesToBlock(marker, block, blocks) {
  if (marker.block === block || parentBlock(marker.block) === block) {
    return true;
  }

  return !rendersOwnSection(blocks, marker.block) && marker.block.startsWith(`${block}.`);
}

function markerName(marker, block) {
  return marker.block === block ? block : marker.block.slice(block.length + 1);
}

function changeMarkerLines(markers, block, change) {
  const changeMarkers = markers.filter((marker) => marker.change === change);
  if (!changeMarkers.length) {
    return [];
  }

  const direct = changeMarkers.length === 1 && changeMarkers[0].block === block;
  const lines = [];

  if (change === 'mustChange') {
    lines.push(direct
      ? '> The default helper implementation is a placeholder and MUST be replaced by a deployment before use.\n'
      : '> The following default helper implementations in this option include placeholders and MUST be replaced by a deployment before use.\n');
  } else {
    lines.push(direct
      ? '> The default helper implementation is intended as a starting point and SHOULD be customized by a deployment.\n'
      : '> The following default helper implementations in this option are intended as starting points and SHOULD be customized by a deployment.\n');
  }

  if (!direct) {
    for (const marker of changeMarkers) {
      lines.push(`> - \`${markerName(marker, block)}\`\n`);
    }
  }

  return lines;
}

function changeAdmonition(value, block, blocks, hidden) {
  if (hidden) {
    return undefined;
  }

  const markers = collectChangeMarkers(value)
    .filter((marker) => appliesToBlock(marker, block, blocks));

  if (!markers.length) {
    return undefined;
  }

  const mustChange = changeMarkerLines(markers, block, 'mustChange');
  const shouldChange = changeMarkerLines(markers, block, 'shouldChange');
  const result = ['> [!IMPORTANT]\n', ...mustChange];
  if (mustChange.length && shouldChange.length) {
    result.push('>\n');
  }
  result.push(...shouldChange);

  return `${result.join('')}\n`;
}

try {
  if (extraArguments.length || (mode && !emitConfigurationJson)) {
    throw new TypeError('usage: node docs/update-configuration.js [--configuration-json]');
  }

  const blocks = {};
  await new Promise((resolve, reject) => {
    const read = readline({
      input: createReadStream(new URL('../lib/helpers/defaults.js', import.meta.url)),
    });
    let nextIsOption;
    let inBlock;
    let option;
    let inTicks;

    read.on('line', (line) => {
      let strLine = line.trim();

      if (strLine.endsWith('```js') || strLine.endsWith('```apache') || strLine.endsWith('```nginx')) {
        inTicks = true;
      }

      if (strLine.endsWith('```')) {
        inTicks = false;
      }

      if (inTicks) {
        strLine = `@indent@${strLine}\n`;
      }

      line = Buffer.from(strLine);

      if (strLine.startsWith('/*') && !strLine.includes('eslint')) {
        inBlock = true;
        nextIsOption = true;
        return;
      }

      if (!inBlock) return;

      if (nextIsOption) {
        nextIsOption = false;
        option = blocks[strLine.slice(2)] = new Block();
        return;
      }

      const next = props.find((prop) => {
        if (
          prop.startsWith('@')
            ? strLine.slice(2, 2 + prop.length) === prop
            : strLine.slice(2, 2 + prop.length + 1) === `${prop}:`
        ) {
          let override;
          if (prop === 'example' && option.example) {
            const i = Math.max(...Object.keys(option)
              .filter((p) => p.startsWith('example'))
              .map((e) => parseInt(e.slice(-1), 10) || 0));
            override = `example${i + 1}`;
          }
          if (prop === 'recommendation' && option.recommendation) {
            const i = Math.max(...Object.keys(option)
              .filter((p) => p.startsWith('recommendation'))
              .map((e) => parseInt(e.slice(-1), 10) || 0));
            override = `recommendation${i + 1}`;
          }
          option.active = override || prop;
          option.write(line.slice(prop.length + 4));
          return true;
        }
        return false;
      });

      if (next) return;

      if (strLine.startsWith('*/')) {
        inBlock = false;
        option = false;
        return;
      }

      if (option?.active) {
        option.write(line);
      }
    });

    read.on('close', () => {
      resolve();
    });

    read.on('error', reject);
  });

  const sortBlocks = (list) => list.sort((a, b) => {
    const aImportant = '@important' in blocks[a];
    const bImportant = '@important' in blocks[b];
    if (aImportant !== bImportant) return aImportant ? -1 : 1;
    return a.localeCompare(b);
  });

  const allBlocks = Object.keys(blocks).filter((value) => value && !('@skip' in blocks[value]));

  // Separate into categories
  const featureBlocks = []; // top-level features.X (not sub-options like features.X.Y)
  const topLevel = [];

  for (const name of allBlocks) {
    if (name.startsWith('features.')) {
      featureBlocks.push(name);
    } else {
      topLevel.push(name);
    }
  }

  // Split features into parent-level (features.X) and sub-options (features.X.Y)
  const featureParents = featureBlocks.filter((f) => f.split('.').length === 2);
  const featureChildren = featureBlocks.filter((f) => f.split('.').length > 2);

  // Split parent features into stable and experimental
  const stableFeatures = featureParents.filter((f) => {
    const value = get(defaults, f);
    return !(typeof value === 'object' && value !== null && 'ack' in value);
  });
  const experimentalFeatures = featureParents.filter((f) => {
    const value = get(defaults, f);
    return typeof value === 'object' && value !== null && 'ack' in value;
  });

  // Sort each group: important first, then alphabetically
  sortBlocks(stableFeatures);
  sortBlocks(experimentalFeatures);
  sortBlocks(topLevel);
  sortBlocks(featureChildren);

  // Build the ordered feature list: stable features first, then experimental
  const orderedFeatures = [...stableFeatures, ...experimentalFeatures];

  // Build the final ordered block list
  const orderedBlocks = [];
  for (const block of topLevel) {
    orderedBlocks.push(block);
    if (block === 'features') {
      // Insert all feature blocks (parents + their children) right after 'features'
      for (const parent of orderedFeatures) {
        orderedBlocks.push(parent);
        // Add any sub-options for this feature
        const children = featureChildren.filter((c) => c.startsWith(`${parent}.`));
        sortBlocks(children);
        orderedBlocks.push(...children);
      }
    }
  }

  if (orderedBlocks.length !== allBlocks.length) {
    throw new TypeError('not all configuration documentation blocks were ordered');
  }

  // Generate Table of Contents
  const tocAnchor = (block) => block.replace(/[.]/g, '').toLowerCase();

  append('\nCallable default values below use TypeScript syntax. Unqualified types are exported by `@types/oidc-provider`.\n\n');
  append('**Table of Contents**\n\n');
  append('> ❗ marks the configuration you most likely want to take a look at.\n\n');

  let inExperimental = false;
  for (const block of orderedBlocks) {
    // Skip child/sub options in the ToC
    if (block.includes('.') && !block.startsWith('features.')) continue;
    if (block.startsWith('features.') && block.split('.').length > 2) continue;

    const section = blocks[block];
    const isImportant = '@important' in section;
    const mark = isImportant ? ' ❗' : '';
    const rawTitle = section.title ? section.title.toString().trim().replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') : '';
    const title = rawTitle ? ` - ${rawTitle}` : '';

    if (block.startsWith('features.')) {
      const isExp = experimentalFeatures.includes(block);
      if (isExp && !inExperimental) {
        inExperimental = true;
        append('  - Experimental features:\n');
      }

      const featureName = block.split('.').slice(1).join('.');
      const indent = inExperimental ? '    ' : '  ';
      append(`${indent}- [${featureName}${mark}](#${tocAnchor(block)})${title}\n`);
    } else {
      if (inExperimental) inExperimental = false;
      append(`- [${block}${mark}](#${tocAnchor(block)})${title}\n`);
    }
  }
  append('\n');

  let first = true;
  let hidden;
  let prev;
  for (const block of orderedBlocks) {
    const section = blocks[block];

    if ('@skip' in section) {
      continue;
    }

    let heading;
    let headingTitle;
    if (block.startsWith('features.')) {
      const parts = block.split('.');
      heading = '#'.repeat(Math.min(parts.length + 1, 4));
      if (parts.length > 2) {
        headingTitle = parts.slice(2).join('.');
      } else {
        headingTitle = block;
      }
    } else {
      heading = '###';
      headingTitle = block;
    }

    if (heading.length > 3 && !hidden) {
      hidden = true;
      append(`\n<details><summary>(Click to expand) ${prev} options details</summary><br>\n\n`);
    } else if (hidden && heading.length === 3) {
      hidden = false;
      append('\n</details>\n');
    }
    prev = block;

    if (first) {
      first = false;
    } else if (!hidden) {
      append('\n---\n');
    }

    append(`\n${heading} ${headingTitle}\n\n`);
    if (section.title) {
      append(`${section.title}\n\n`);
    }

    const value = get(defaults, block);
    const callableType = typeSource(section);

    if (typeof value === 'object' && 'ack' in value) {
      append('> [!NOTE]\n');
      append('> This is an experimental feature.\n\n');
    }

    const admonition = changeAdmonition(value, block, blocks, hidden);
    if (admonition) {
      append(admonition);
    }

    if (section.description) {
      append(`${capitalizeSentences(smartJoin(section.description))}\n\n`);
    }

    if (section.see) {
      if (section.see.length > 1) {
        append('See:\n');
        for (const see of section.see) {
          append(`- ${see.toString('utf-8')}\n`);
        }
      } else {
        append(`See ${section.see[0].toString('utf-8')}\n`);
      }
    }

    Object.keys(section).filter((x) => x.startsWith('recommendation')).forEach((prop) => {
      append(`_**recommendation**_: ${smartJoin(section[prop])}\n\n`);
    });

    if ('@nodefault' in section && callableType) {
      append('\n_**type**_:\n');
      append('```ts\n');
      append(callableType);
      append('\n```\n');
    } else if (!('@nodefault' in section)) {
      switch (typeof value) {
        case 'boolean':
        case 'number': {
          const output = String(value);
          const rendered = callableType
            ? typedDefault(publicName(block), callableType, output)
            : output;
          append(expand(rendered, callableType ? 'ts' : 'js'));
          break;
        }
        case 'string':
        case 'undefined':
        case 'object': {
          if (value === null && callableType) {
            throw new TypeError(`callable type metadata cannot describe a null default (${block})`);
          }
          const output = inspect(value, { compact: false, sorted: true });
          const hasExpandedDetails = Object.entries(blocks).some(([name, details]) => (
            name.startsWith(`${block}.`) && !('@skip' in details)
          ));
          const rendered = callableType
            ? typedDefault(publicName(block), callableType, output)
            : output;
          append(expand(rendered, callableType ? 'ts' : 'js').split('\n').map((line) => {
            if (hasExpandedDetails) {
              line = line.replace(/(\[(?:Async)?Function: \w+\],?)/, '$1 // see expanded details below');
            }
            return line;
          }).join('\n'));
          break;
        }
        case 'function': {
          if (!callableType) {
            throw new TypeError(`missing type metadata for callable default ${block}`);
          }
          append(expand(typedFunctionDefault(
            block,
            callableType,
            functionSource(value, block),
          ), 'ts'));
          break;
        }
        default:
          throw new TypeError(`unexpected value type ${typeof value} for ${block}`);
      }
    }

    Object.keys(section).filter((p) => p.startsWith('example')).forEach((prop) => {
      const [title, ...content] = section[prop];
      append(`<a id="${words(`${headingTitle} ${title}`).map((w) => w.toLowerCase()).join('-')}"></a>`.replace('\n', ''));
      append(`<details><summary>Example: (Click to expand) ${title ? title.toString('utf8').replaceAll('\n', '').trim() : ''}</summary><br>\n\n`);

      const parts = [];
      let incode;
      for (const line of content) {
        const backticks = line.indexOf('```') !== -1;
        if (incode) {
          parts[parts.length - 1].push(line);
          if (backticks) {
            incode = false;
          }
          continue;
        }

        if (backticks) {
          incode = true;
          parts.push([line]);
        } else {
          parts.push(line);
        }
      }

      while (parts.length) {
        const until = parts.findIndex((p) => Array.isArray(p));
        if (until === 0) {
          const lines = parts.shift();
          lines.forEach(append);
        } else {
          const lines = parts.splice(0, until === -1 ? parts.length : until);
          append(`\n${capitalizeSentences(smartJoin(lines))}\n\n`);
        }
      }

      append('\n</details>\n');
    });
  }

  if (emitConfigurationJson) {
    process.stdout.write(`${JSON.stringify(configurationDocumentation(blocks, orderedBlocks), null, 2)}\n`);
  } else {
    const readme = new URL('./README.md', import.meta.url);
    const conf = readFileSync(readme);

    const comStart = '<!-- START CONF OPTIONS -->';
    const comEnd = '<!-- END CONF OPTIONS -->';

    const pre = conf.slice(0, conf.indexOf(comStart) + comStart.length);
    const post = conf.slice(conf.indexOf(comEnd));
    const normalized = Buffer.from(mid.toString().replace(/[ \t]+$/gm, ''));
    writeFileSync(readme, Buffer.concat([pre, Buffer.from('\n'), normalized, post]));
  }
} catch (err) {
  console.error(err);
  process.exitCode = 1;
}
