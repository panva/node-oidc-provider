/* eslint-disable no-restricted-syntax, max-len, no-await-in-loop, no-plusplus */
const { spawn } = require('child_process');

const runtimeSupport = require('../lib/helpers/runtime_support');

let first = true;

function pass({ format, mountTo, mountVia } = {}) {
  const child = spawn(
    'nyc',
    ['--silent', first ? '' : '--no-clean', 'npm', 'run', 'test', '--', `--format=${format}`].filter(Boolean),
    {
      stdio: 'inherit',
      shell: true,
      env: {
        ...process.env,
        CI: true,
        MOUNT_TO: mountTo,
        MOUNT_VIA: mountVia,
      },
    },
  );

  first = false;

  return new Promise((resolve, reject) => {
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject();
      }
    });
  });
}

function report() {
  const child = spawn(
    'nyc',
    ['report'],
    {
      stdio: 'inherit',
      shell: true,
    },
  );

  return new Promise((resolve) => {
    child.on('close', resolve);
  });
}

(async () => {
  const formats = ['opaque', 'jwt', 'jwt-ietf', runtimeSupport.EdDSA ? 'paseto' : '', 'dynamic'].filter(Boolean);

  for (const format of formats) {
    await pass({ format });
  }

  const mountTo = '/oidc';

  for (const mountVia of ['connect', 'express', 'fastify', 'hapi', 'koa']) {
    await pass({ format: 'dynamic', mountVia, mountTo });
  }

  await report();
})().catch(() => {
  process.exitCode = 1;
});
