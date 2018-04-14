/* eslint-disable no-console */

function captureConsoleInfo(fn, color) {
  let out;
  const { isTTY } = process.stdout;
  const orig = console.info;

  process.stdout.isTTY = Boolean(color);
  console.info = function (str) {
    out = `${str}\n`;
  };
  try {
    fn();
    return out;
  } finally {
    process.stdout.isTTY = isTTY;
    console.info = orig;
  }
}

function captureConsoleWarn(fn, color) {
  let out;
  const { isTTY } = process.stderr;
  const orig = console.warn;

  process.stderr.isTTY = Boolean(color);
  console.warn = function (str) {
    out = `${str}\n`;
  };
  try {
    fn();
    return out;
  } finally {
    process.stderr.isTTY = isTTY;
    console.warn = orig;
  }
}

module.exports = {
  captureConsoleInfo,
  captureConsoleWarn,
};
