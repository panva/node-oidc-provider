/* eslint-disable no-restricted-syntax, max-len, no-await-in-loop, no-plusplus */
const { spawn } = require('child_process');

let first = true;

function pass({ mountTo, mountVia } = {}) {
  const child = spawn(
    'c8',
    [first ? '' : '--clean=false', 'npm', 'run', 'test'].filter(Boolean),
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
    'c8',
    ['report', '--reporter=lcov', '--reporter=text-summary'],
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
  await pass();

  if (process.platform === 'linux' || !('CI' in process.env)) {
    const mountTo = '/oidc';
    const frameworks = ['connect', 'express', 'fastify', 'koa'];

    if (process.version.substr(1).split('.').map((x) => parseInt(x, 10))[0] >= 12) {
      frameworks.push('hapi');
    }

    for (const mountVia of frameworks) {
      await pass({ mountVia, mountTo });
    }
  }

  await report();
})().catch(() => {
  process.exitCode = 1;
});
