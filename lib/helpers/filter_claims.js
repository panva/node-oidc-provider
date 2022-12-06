export default (source, target, grant) => {
  const claims = { ...(source?.[target]) };
  const requested = Object.keys(claims);
  const granted = new Set(grant.getOIDCClaimsFiltered(new Set(requested)));

  for (const claim of requested) {
    // eslint-disable-next-line no-continue
    if (['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim)) continue;
    if (!granted.has(claim)) {
      delete claims[claim];
    }
  }
  return claims;
};
