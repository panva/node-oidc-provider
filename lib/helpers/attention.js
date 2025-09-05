const SET_BOLD_YELLOW_TEXT = '\x1b[33;1m';
const SET_BOLD_RED_TEXT = '\x1b[31;1m';
const RESET_ALL_ATTRIBUTES = '\x1b[0m';

let stdout;
if (globalThis.process?.stdout?.isTTY) {
  stdout = (str) => `${SET_BOLD_YELLOW_TEXT}${str}${RESET_ALL_ATTRIBUTES}`;
}

let stderr;
if (globalThis.process?.stderr?.isTTY) {
  stderr = (str) => `${SET_BOLD_RED_TEXT}${str}${RESET_ALL_ATTRIBUTES}`;
}

export function info(str) {
  const notice = `oidc-provider NOTICE: ${str}`;
  console.info(stdout ? stdout(notice) : notice); // eslint-disable-line no-console
}

export function warn(str) {
  const warning = `oidc-provider WARNING: ${str}`;
  console.warn(stderr ? stderr(warning) : warning); // eslint-disable-line no-console
}
