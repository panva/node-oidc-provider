/* eslint-disable no-param-reassign */

const { createInterface: readline } = require('readline');
const { inspect } = require('util');
const { createReadStream, writeFileSync, readFileSync } = require('fs');

const get = require('lodash/get'); // eslint-disable-line import/no-extraneous-dependencies
const words = require('lodash/words'); // eslint-disable-line import/no-extraneous-dependencies

const docs = require('../lib/helpers/docs');
const values = require('../lib/helpers/defaults')();

values.ttl.RefreshToken[inspect.custom] = () => (
  values.ttl.RefreshToken.toString()
    .replace(/ {6}/g, '  ')
    .replace(/\s+}$/, '\n}')
);

values.interactions.policy[inspect.custom] = () => readFileSync('./docs/checks.txt').toString();

function capitalizeSentences(copy) {
  return copy.replace(/\. [a-z]/g, (match) => `. ${match.slice(-1).toUpperCase()}`);
}

class Block {
  write(buffer) {
    if (!this[this.active]) {
      this[this.active] = [buffer];
    } else {
      while (buffer.indexOf('*') === 0 || buffer.indexOf(' ') === 0) {
        buffer = buffer.slice(1);
      }

      if (buffer.indexOf('@indent@') === 0) {
        buffer = buffer.slice(10);
      }

      if (buffer.indexOf('##DOCS') !== -1) {
        buffer = Buffer.from(buffer.toString().replace(/##DOCS\/(.+)##/g, () => docs(RegExp.$1)));
      }

      if (buffer.indexOf('-') === 0 || /^\d+\./.exec(buffer) || buffer.indexOf('```') !== -1 || buffer.indexOf('|') === 0) {
        const last = this[this.active].pop();
        if (last.toString().endsWith('\n')) {
          this[this.active].push(last);
        } else {
          this[this.active].push(Buffer.concat([last, Buffer.from('\n')]));
        }
      }

      if (buffer.length) {
        this[this.active].push(buffer);
      } else if (this.active === 'description') {
        this[this.active].push(Buffer.from('  \n'));
      }
    }
  }
}

const props = [
  'description',
  'title',
  'recommendation',
  'example',
  '@nodefault',
  '@skip',
];

(async () => {
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


      if (strLine.startsWith('/*') && !strLine.includes('eslint') && !strLine.includes('istanbul')) {
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
        if (
          prop.startsWith('@')
            ? strLine.substring(2, 2 + prop.length) === prop
            : strLine.substring(2, 2 + prop.length + 1) === `${prop}:`
        ) {
          let override;
          if (prop === 'example' && option.example) {
            const i = Math.max(...Object.keys(option)
              .filter((p) => p.startsWith('example'))
              .map((e) => parseInt(e.slice(-1), 10) || 0));
            override = `example${i + 1}`;
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

  function expand(what) {
    what = `\`\`\`js\n${what}\n\`\`\`\n`;

    append('\n_**default value**_:\n');
    return what;
  }

  let featuresIdx = 0;
  const configuration = Object.keys(blocks).sort().reduce((acc, key) => {
    if (!key) return acc;
    if (key.startsWith('features')) {
      featuresIdx += 1;
      acc.unshift(key);
    } else {
      acc.push(key);
    }
    return acc;
  }, []);

  const features = configuration.splice(0, featuresIdx).sort();
  const clientsIdx = configuration.findIndex((x) => x === 'clients');
  const clients = configuration.splice(clientsIdx, 1);
  const adapterIdx = configuration.findIndex((x) => x === 'adapter');
  const adapter = configuration.splice(adapterIdx, 1);
  const jwksIdx = configuration.findIndex((x) => x === 'jwks');
  const jwks = configuration.splice(jwksIdx, 1);
  const findAccountIdx = configuration.findIndex((x) => x === 'findAccount');
  const findAccount = configuration.splice(findAccountIdx, 1);

  let hidden;
  let prev;
  for (const block of [...adapter, ...clients, ...findAccount, ...jwks, ...features, ...configuration]) { // eslint-disable-line no-restricted-syntax, max-len
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

    append(`\n${heading} ${headingTitle}\n\n`);
    if (section.title) {
      append(`${section.title}  \n\n`);
    }

    if (section.description) {
      append(`${capitalizeSentences(section.description.join(' '))}  \n\n`);
    }

    ['recommendation'].forEach((option) => {
      if (section[option]) {
        append(`_**${option}**_: ${section[option].join(' ')}  \n\n`);
      }
    });

    if (!('@nodefault' in section)) {
      const value = get(values, block);
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
            if (line.includes('/* istanbul ignore')) {
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
      append(`<details><summary>(Click to expand) ${title}</summary><br>\n\n`);

      const parts = [];
      let incode;
      for (const line of content) { // eslint-disable-line no-restricted-syntax
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
          append(`\n${capitalizeSentences(lines.join(' '))}  \n\n`);
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

  writeFileSync('./docs/README.md', Buffer.concat([pre, mid, post]));
})().catch((err) => {
  console.error(err); // eslint-disable-line no-console
  process.exitCode = 1;
});
