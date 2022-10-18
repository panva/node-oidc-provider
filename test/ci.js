/* eslint-disable no-restricted-syntax, max-len, no-await-in-loop, no-plusplus */
const { spawn } = require('child_process');

function pass({ mountTo, mountVia } = {}) {
  const child = spawn(
    'npm',
    ['run', 'test'],
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

(async () => {
  await pass();

  if (process.platform === 'linux' || !('CI' in process.env)) {
    const mountTo = '/oidc';
    const frameworks = ['connect', 'express', 'koa'];

    const [major] = process.version.slice(1).split('.').map((x) => parseInt(x, 10));

    if (major >= 12) {
      frameworks.push('hapi');
    }

    if (major >= 14) {
      frameworks.push('fastify');
    }

    for (const mountVia of frameworks) {
      await pass({ mountVia, mountTo });
    }
  }
})().catch(() => {
  process.exitCode = 1;
});
