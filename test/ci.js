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

function cartesian(...arg) {
  const r = [];
  const max = arg.length - 1;

  function helper(arr, i) {
    for (let j = 0, l = arg[i].length; j < l; j++) {
      const a = arr.slice(0);
      a.push(arg[i][j]);
      if (i === max) r.push(a);
      else helper(a, i + 1);
    }
  }
  helper([], 0);
  return r;
}

(async () => {
  const formats = ['opaque', 'jwt', 'jwt-ietf', runtimeSupport.EdDSA ? 'paseto' : '', 'dynamic'].filter(Boolean);
  const matrix = [
    ['koa', 'express', 'connect'],
    ['/', '/oidc'],
  ];

  for (const format of formats) {
    await pass({ format });
  }

  for (const format of formats) {
    const runs = cartesian(...matrix);
    for (const [mountVia, mountTo] of runs) {
      await pass({ format, mountVia, mountTo });
    }
  }

  await report();
})().catch(() => {
  process.exitCode = 1;
});
