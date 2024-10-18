export default function redirectUri(uri, payload, mode) {
  const parsed = new URL(uri);

  switch (mode) {
    case 'fragment':
      parsed.hash = new URLSearchParams(payload).toString();
      break;
    default:
      for (const [k, v] of Object.entries(payload)) {
        parsed.searchParams.set(k, v);
      }
      break;
  }

  return parsed.href;
}
