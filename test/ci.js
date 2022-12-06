/* eslint-disable no-await-in-loop */
import { spawn } from 'node:child_process';

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

try {
  await pass();

  if (process.platform === 'linux' || !('CI' in process.env)) {
    const mountTo = '/oidc';
    const frameworks = ['connect', 'express', 'koa', 'hapi', 'fastify'];

    for (const mountVia of frameworks) {
      await pass({ mountVia, mountTo });
    }
  }
} catch {
  process.exitCode = 1;
}
