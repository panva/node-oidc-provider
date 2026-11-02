import { clearTimeout, setTimeout } from 'node:timers';

export default async function withTimeout(run, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(run),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`test attempt timed out after ${milliseconds}ms`));
        }, milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
