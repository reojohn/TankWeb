const cache = new Map();
const inflight = new Map();
const TTL = 120_000;

function keyFor(view) {
  return String(view || 'bootstrap');
}

export async function fetchView(view, { force = false } = {}) {
  const key = keyFor(view);
  const cached = cache.get(key);
  if (!force && cached && Date.now() - cached.at < TTL) return cached.data;
  if (!force && inflight.has(key)) return inflight.get(key);

  const promise = fetch(`/api/v3.php?view=${encodeURIComponent(key)}`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'X-Fortress-React': '1' },
  }).then(async (response) => {
    if (response.status === 401 || response.status === 403) {
      window.location.href = '/login.php';
      throw new Error('Authentication expired');
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.message || 'Unable to load FortressAuth data.');
    const data = payload.data ?? payload;
    cache.set(key, { at: Date.now(), data });
    return data;
  }).finally(() => inflight.delete(key));

  inflight.set(key, promise);
  return promise;
}

export function getCachedView(view) {
  return cache.get(keyFor(view))?.data ?? null;
}

export function isViewFresh(view) {
  const cached = cache.get(keyFor(view));
  return !!cached && Date.now() - cached.at < TTL;
}

export function prefetchView(view) {
  fetchView(view).catch(() => {});
}

export function clearView(view) {
  cache.delete(keyFor(view));
}

export async function postView(view, body) {
  const response = await fetch(`/api/v3.php?view=${encodeURIComponent(view)}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Fortress-React': '1' },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) throw new Error(payload.message || 'The FortressAuth action failed.');
  clearView(view);
  return payload;
}
