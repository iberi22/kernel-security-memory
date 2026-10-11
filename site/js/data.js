/**
 * Data layer: fetch & cache of JSON shards.
 * Default base path: './data/', overridable with '?data=<path>'.
 */

const cache = new Map();

export function getDataBasePath() {
  const params = new URLSearchParams(window.location.search);
  const custom = params.get('data');
  if (custom) {
    return custom.endsWith('/') ? custom : custom + '/';
  }
  return './data/';
}

const basePath = getDataBasePath();

async function fetchShard(relativePath) {
  const url = `${basePath}${relativePath}`;
  if (cache.has(url)) {
    return cache.get(url);
  }

  // No silent fallback to the sample data: a missing shard is an error the
  // reader must see. Locally: python3 scripts/site/build_site_data.py --out site/data
  const promise = (async () => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to load ${url} (status: ${res.status})`);
    }
    return res.json();
  })();
  // Failed fetches are not cached, so a retry after a transient error works.
  promise.catch(() => cache.delete(url));

  cache.set(url, promise);
  return promise;
}

export async function getIndex() {
  return fetchShard('index.json');
}

export async function getCwe(cweId) {
  return fetchShard(`cwe/${encodeURIComponent(cweId)}.json`);
}

export async function getCve(project, cveId) {
  return fetchShard(`cve/${encodeURIComponent(project)}/${encodeURIComponent(cveId)}.json`);
}

export async function getSearch() {
  return fetchShard('search.json');
}

export function clearCache() {
  cache.clear();
}
