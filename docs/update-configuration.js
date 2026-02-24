/* eslint-disable no-param-reassign, no-plusplus */

import { createInterface as readline } from 'node:readline';
import { inspect } from 'node:util';
import { createReadStream, writeFileSync, readFileSync } from 'node:fs';

import get from 'lodash/get.js'; // eslint-disable-line import/no-extraneous-dependencies
import words from 'lodash/words.js'; // eslint-disable-line import/no-extraneous-dependencies

import { defaults } from '../lib/helpers/defaults.js';
import login from '../lib/helpers/interaction_policy/prompts/login.js';
import consent from '../lib/helpers/interaction_policy/prompts/consent.js';

for (const [key, value] of Object.entries(defaults.ttl)) {
  if (['RefreshToken', 'ClientCredentials', 'AccessToken', 'BackchannelAuthenticationRequest'].includes(key)) {
    value[inspect.custom] = () => (
      value.toString()
        .replace(/ {6}/g, '  ')
        // eslint-disable-next-line redos/no-vulnerable
        .replace(/\s+}$/, '\n}')
        .split('\n')
        .filter((line) => !line.includes('Change'))
        .join('\n')
    );
  } else if (typeof value === 'function') {
    const comp = value();
    value[inspect.custom] = () => (
      value.toString()
        .split('\n')
        .map((line) => (line.includes('return') ? `${comp} /* ${line.trim().split('// ')[1]} */` : undefined))
        .filter(Boolean)[0]
    );
  }
}

defaults.interactions.policy[inspect.custom] = () => `[
/* LOGIN PROMPT */
${login.toString().replace('() => new Prompt', 'new Prompt')}

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

function expand(what) {
  what = `\`\`\`js\n${what}\n\`\`\`\n`;

  append('\n_**default value**_:\n');
  return what;
}

try {
  const blocks = {};
  await new Promise((resolve, reject) => {
    const read = readline({ input: createReadStream('./lib/helpers/defaults.js') });
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
        option = blocks[strLine.slice(2)] = new Block(); // eslint-disable-line no-multi-assign
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

  // Generate Table of Contents
  const tocAnchor = (block) => block.replace(/[.]/g, '').toLowerCase();

  append('\n**Table of Contents**\n\n');
  append('> ❗ marks the configuration you most likely want to take a look at.\n\n');

  let inExperimental = false;
  for (const block of orderedBlocks) {
    // Skip child/sub options in the ToC
    if (block.includes('.') && !block.startsWith('features.')) continue; // eslint-disable-line no-continue
    if (block.startsWith('features.') && block.split('.').length > 2) continue; // eslint-disable-line no-continue

    const section = blocks[block];
    const isImportant = '@important' in section;
    const mark = isImportant ? ' ❗' : '';
    const rawTitle = section.title ? section.title.toString().trim().replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') : ''; // eslint-disable-line redos/no-vulnerable
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
      continue; // eslint-disable-line no-continue
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
      append(`${section.title}  \n\n`);
    }

    const value = get(defaults, block);

    if (typeof value === 'object' && 'ack' in value) {
      append('> [!NOTE]\n');
      append('> This is an experimental feature.\n\n');
    }

    if (section.description) {
      append(`${capitalizeSentences(smartJoin(section.description))}  \n\n`);
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
      append(`_**recommendation**_: ${smartJoin(section[prop])}  \n\n`);
    });

    if (!('@nodefault' in section)) {
      switch (typeof value) {
        case 'boolean':
        case 'number':
          append('\n_**default value**_:\n');
          append('```js\n');
          append(`${String(value)}`);
          append('\n```\n');
          break;
        case 'string':
        case 'undefined':
        case 'object': {
          const output = inspect(value, { compact: false, sorted: true });
          append(expand(output).split('\n').map((line) => {
            line = line.replace(/(\[(?:Async)?Function: \w+\],?)/, '$1 // see expanded details below');
            return line;
          }).join('\n'));
          break;
        }
        case 'function': {
          let fixIndent;
          let mute = false;
          append(expand(String(value).split('\n').map((line, index) => {
            if (index === 1) {
              line.match(/^(\s+)\S+/);
              fixIndent = RegExp.$1.length - 2;
            }
            if (line.includes('shouldChange')) return undefined;
            if (line.includes('mustChange')) return undefined;
            if (line.startsWith(' ')) {
              line = line.replace(new RegExp(`^( {0,${fixIndent}})`), '');
            }
            line = line.replace(/ \/\/ eslint-disable.+/, '');
            if (line.includes('/* eslint-disable')) {
              return undefined;
            }
            if (line.includes('/* eslint-enable')) {
              return undefined;
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
          }).filter(Boolean)
            .join('\n')));
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
          continue; // eslint-disable-line no-continue
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
          append(`\n${capitalizeSentences(smartJoin(lines))}  \n\n`);
        }
      }

      append('\n</details>\n');
    });
  }

  const conf = readFileSync('./docs/README.md');

  const comStart = '<!-- START CONF OPTIONS -->';
  const comEnd = '<!-- END CONF OPTIONS -->';

  const pre = conf.slice(0, conf.indexOf(comStart) + comStart.length);
  const post = conf.slice(conf.indexOf(comEnd));

  writeFileSync('./docs/README.md', Buffer.concat([pre, Buffer.from('\n'), mid, post]));
} catch (err) {
  console.error(err); // eslint-disable-line no-console
  process.exitCode = 1;
}
