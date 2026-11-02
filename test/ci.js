import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function pass({ mountTo = '/', mountVia = '' } = {}) {
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL('./run.js', import.meta.url))],
    {
      stdio: 'inherit',
      env: {
        ...process.env,
        CI: 'true',
        MOUNT_TO: mountTo,
        MOUNT_VIA: mountVia,
      },
    },
  );

  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`test suite exited with code ${code}`));
    });
  });
}

try {
  await pass();

  if (process.platform === 'linux' || !('CI' in process.env)) {
    const mountTo = '/oidc';
    for (const mountVia of ['express', 'koa', 'hapi', 'fastify']) {
      await pass({ mountVia, mountTo });
    }
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
