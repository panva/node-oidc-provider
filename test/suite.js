import { once } from 'node:events';
import { createServer } from 'node:http';
import { describe, after } from 'node:test';
import { pathToFileURL } from 'node:url';

import testFiles from './files.js';

const { info, warn } = console;
console.info = function (...args) {
  if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
  if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

// Register every suite before running hooks. All files share the HTTP listener,
// adapter storage, dispatcher, and fake clocks, so they must run sequentially.
describe('oidc-provider', { concurrency: false }, async () => {
  after(async () => {
    try {
      if (globalThis.server?.listening) {
        await new Promise((resolve, reject) => {
          globalThis.server.close((error) => (error ? reject(error) : resolve()));
        });
      }
    } finally {
      console.info = info;
      console.warn = warn;
    }
  });

  globalThis.server = createServer().listen(0, '::');
  await once(globalThis.server, 'listening');

  for (const file of testFiles()) {
    await import(pathToFileURL(file).href);
  }
});
