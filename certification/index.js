if (process.env.FAPI) {
  await import('./fapi/index.js');
} else {
  await import('./oidc/index.js');
}
