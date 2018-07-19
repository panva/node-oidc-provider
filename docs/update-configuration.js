/* eslint-disable no-param-reassign */

const { createInterface: readline } = require('readline');
const { inspect } = require('util');
const { createReadStream, writeFileSync, readFileSync } = require('fs');

const { get } = require('lodash');

const values = require('../lib/helpers/defaults');

function capitalizeSentences(copy) {
  return copy.replace(/\. [a-z]/g, match => `. ${match.slice(-1).toUpperCase()}`);
}

class Block {
  write(buffer) {
    if (!this[this.active]) {
      this[this.active] = [buffer];
    } else {
      while (buffer.indexOf('*') === 0 || buffer.indexOf(' ') === 0) {
        buffer = buffer.slice(1);
      }
      if (buffer.indexOf('-') === 0) {
        const last = this[this.active].pop();
        this[this.active].push(Buffer.concat([last, Buffer.from('\n')]));
      }
      if (buffer.length) {
        this[this.active].push(buffer);
      }
    }
  }
}

const props = [
  'description',
  'affects',
  'recommendation',
  '@nodefault',
];

(async () => {
  const blocks = {};
  await new Promise((resolve, reject) => {
    const read = readline({ input: createReadStream('./lib/helpers/defaults.js') });
    let nextIsOption;
    let inBlock;
    let option;

    read.on('line', (line) => {
      const strLine = line.trim();
      line = Buffer.from(strLine);

      if (strLine.startsWith('/*')) {
        inBlock = true;
        nextIsOption = true;
        return;
      }

      if (!inBlock) return;

      if (nextIsOption) {
        nextIsOption = false;
        option = blocks[strLine.substring(2)] = new Block(); // eslint-disable-line no-multi-assign
        return;
      }

      const next = props.find((prop) => {
        if (strLine.substring(2, 2 + prop.length) === prop) {
          option.active = prop;
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

      if (option && option.active) {
        option.write(line);
      }
    });

    read.on('close', () => {
      resolve();
    });

    read.on('error', reject);
  });

  let mid = Buffer.from('');

  function append(what) {
    mid = Buffer.concat([mid, Buffer.from(what)]);
  }

  Object.keys(blocks).sort().forEach((block) => {
    append(`\n### ${block}\n\n`);
    if (blocks[block].description) {
      append(`${capitalizeSentences(blocks[block].description.join(' '))}  \n\n`);
    }
    ['affects', 'recommendation'].forEach((option) => {
      if (blocks[block][option]) {
        append(`${option}: ${blocks[block][option].join(' ')}  \n`);
      }
    });
    if (!('@nodefault' in blocks[block])) {
      append('\ndefault value:\n');
      append('```js\n');
      const value = get(values, block);
      switch (typeof value) {
        case 'boolean':
        case 'number':
          append(`${String(value)}`);
          break;
        case 'string':
        case 'object':
          append(inspect(value));
          break;
        case 'function': {
          let fixIndent;
          let mute = false;
          append(String(value).split('\n').map((line, index) => {
            if (index === 1) {
              line.match(/^(\s+)\S+/);
              fixIndent = RegExp.$1.length - 2;
            }
            if (line.includes('changeme')) return undefined;
            if (line.startsWith(' ')) line = line.slice(fixIndent);
            line = line.replace(/ \/\/ eslint-disable.+/, '');
            line = line.replace(/ \/\/ TODO.+/, '');
            line = line.replace(/ class="[ \-\w]+ ?"/, '');
            if (line.includes('<style>')) {
              mute = true;
              return '<style>/* css and html classes omitted for brevity, see lib/helpers/defaults.js */</style>';
            }
            if (line.includes('</style>')) {
              mute = false;
              return undefined;
            }
            if (mute) return undefined;
            return line;
          }).filter(Boolean)
            .join('\n'));
          break;
        }
        default:
          throw new Error(`unexpected value type ${typeof value}`);
      }
      append('\n```\n');
    }
  });

  const conf = readFileSync('./docs/configuration.md');

  const comStart = '<!-- START CONF OPTIONS -->';
  const comEnd = '<!-- END CONF OPTIONS -->';

  const pre = conf.slice(0, conf.indexOf(comStart) + comStart.length);
  const post = conf.slice(conf.indexOf(comEnd));

  writeFileSync('./docs/configuration.md', Buffer.concat([pre, mid, post]));
})().catch((err) => {
  console.error(err); // eslint-disable-line no-console
  process.exitCode = 1;
});
