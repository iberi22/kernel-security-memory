/**
 * GitHub API & Raw content integration for live Before/After code viewer.
 * Caches responses in sessionStorage.
 * Strictly uses DOM textContent to avoid raw HTML injection.
 */

function getCached(key) {
  try {
    const val = sessionStorage.getItem(key);
    return val ? JSON.parse(val) : null;
  } catch (_) {
    return null;
  }
}

function setCached(key, value) {
  try {
    sessionStorage.setItem(key, JSON.stringify(value));
  } catch (_) {}
}

// After a 403/429 the API is not called again for this long (the
// unauthenticated limit resets hourly); each blocked call would fail anyway.
const RATE_LIMIT_BACKOFF_MS = 10 * 60 * 1000;

export async function fetchCommit(repo, sha) {
  const cacheKey = `gh_commit_${repo}_${sha}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;
  const blockedUntil = Number(getCached('gh_rate_limited_until') || 0);
  if (Date.now() < blockedUntil) {
    return { rateLimited: true, status: 429, commitUrl: `https://github.com/${repo}/commit/${sha}` };
  }

  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/commits/${sha}`);
    if (res.status === 403 || res.status === 429) {
      setCached('gh_rate_limited_until', Date.now() + RATE_LIMIT_BACKOFF_MS);
      return {
        rateLimited: true,
        status: res.status,
        commitUrl: `https://github.com/${repo}/commit/${sha}`
      };
    }
    if (!res.ok) {
      return {
        error: `GitHub API error: ${res.status} ${res.statusText}`,
        commitUrl: `https://github.com/${repo}/commit/${sha}`
      };
    }
    const data = await res.json();
    const parentSha = data.parents && data.parents.length > 0 ? data.parents[0].sha : null;
    const files = (data.files || []).map(f => ({
      filename: f.filename,
      status: f.status,
      patch: f.patch || ''
    }));

    const result = { parentSha, files, commitUrl: data.html_url || `https://github.com/${repo}/commit/${sha}` };
    setCached(cacheKey, result);
    return result;
  } catch (err) {
    return {
      error: `Network error: ${err.message}`,
      commitUrl: `https://github.com/${repo}/commit/${sha}`
    };
  }
}

export async function fetchRawFile(repo, ref, filePath) {
  const cacheKey = `gh_raw_${repo}_${ref}_${filePath}`;
  const cached = getCached(cacheKey);
  if (cached !== null) return cached;

  try {
    const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
    const res = await fetch(`https://raw.githubusercontent.com/${repo}/${ref}/${encodedPath}`);
    if (res.status === 403 || res.status === 429) {
      return {
        rateLimited: true,
        status: res.status
      };
    }
    if (!res.ok) {
      return {
        error: `HTTP ${res.status} ${res.statusText}`
      };
    }
    const text = await res.text();
    setCached(cacheKey, text);
    return text;
  } catch (err) {
    return {
      error: `Network error: ${err.message}`
    };
  }
}

export function parsePatchHunks(patchText) {
  const delLines = new Set();
  const addLines = new Set();
  if (!patchText) return { delLines, addLines };

  const lines = patchText.split('\n');
  let curOld = 0;
  let curNew = 0;
  let inHunk = false;

  for (const line of lines) {
    const match = line.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
    if (match) {
      curOld = parseInt(match[1], 10);
      curNew = parseInt(match[3], 10);
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;

    if (line.startsWith('-')) {
      delLines.add(curOld);
      curOld++;
    } else if (line.startsWith('+')) {
      addLines.add(curNew);
      curNew++;
    } else if (line.startsWith(' ')) {
      curOld++;
      curNew++;
    }
  }

  return { delLines, addLines };
}

function sliceCode(text, range) {
  if (!text || typeof text !== 'string') return [];
  if (!range || !Array.isArray(range) || range.length < 2) {
    const all = text.split('\n');
    return all.map((line, idx) => ({ num: idx + 1, text: line }));
  }
  const [start, end] = range;
  const all = text.split('\n');
  const from = Math.max(0, start - 1);
  const to = Math.min(all.length, end);
  const sliced = [];
  for (let i = from; i < to; i++) {
    sliced.push({ num: i + 1, text: all[i] });
  }
  return sliced;
}

export function buildCodeViewerElement({
  repo,
  sha,
  parentSha,
  filePath,
  patchText,
  beforeText,
  afterText,
  beforeRange,
  afterRange,
  wholeFile,
  rateLimited,
  error,
  commitUrl
}) {
  const container = document.createElement('div');
  container.className = 'code-viewer-container';

  if (rateLimited) {
    const box = document.createElement('div');
    box.className = 'rate-limit-box';
    const p = document.createElement('p');
    p.textContent = 'GitHub rate limit reached (60 requests/hour without login); try later.';
    box.appendChild(p);

    if (commitUrl) {
      const a = document.createElement('a');
      a.href = commitUrl;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Open commit on GitHub';
      a.style.display = 'inline-block';
      a.style.marginTop = '6px';
      box.appendChild(a);
    }
    container.appendChild(box);
    return container;
  }

  if (error) {
    const box = document.createElement('div');
    box.className = 'rate-limit-box';
    const p = document.createElement('p');
    p.textContent = error;
    box.appendChild(p);
    if (commitUrl) {
      const a = document.createElement('a');
      a.href = commitUrl;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Open commit on GitHub';
      a.style.display = 'inline-block';
      a.style.marginTop = '6px';
      box.appendChild(a);
    }
    container.appendChild(box);
    return container;
  }

  const { delLines, addLines } = parsePatchHunks(patchText);

  // Toolbar with Tabs
  const toolbar = document.createElement('div');
  toolbar.className = 'code-viewer-toolbar';

  const tabsContainer = document.createElement('div');
  tabsContainer.className = 'code-viewer-tabs';

  const sideBySideTab = document.createElement('button');
  sideBySideTab.className = 'tab-btn active';
  sideBySideTab.textContent = 'Side-by-side';

  const patchTab = document.createElement('button');
  patchTab.className = 'tab-btn';
  patchTab.textContent = 'Patch';

  tabsContainer.appendChild(sideBySideTab);
  tabsContainer.appendChild(patchTab);
  toolbar.appendChild(tabsContainer);

  const metaInfo = document.createElement('span');
  metaInfo.className = 'tree-count';
  metaInfo.textContent = filePath;
  toolbar.appendChild(metaInfo);

  container.appendChild(toolbar);

  // Content Views
  const splitView = document.createElement('div');
  splitView.className = 'code-split-view';

  // Left column: Before
  const leftCol = document.createElement('div');
  leftCol.className = 'code-column';
  const leftHeader = document.createElement('div');
  leftHeader.className = 'code-col-header';
  const leftTitle = document.createElement('span');
  leftTitle.textContent = `Before (${parentSha ? parentSha.substring(0, 8) : 'parent'})`;
  const leftRangeInfo = document.createElement('span');
  leftRangeInfo.textContent = beforeRange ? `Lines ${beforeRange[0]}-${beforeRange[1]}` : 'N/A';
  leftHeader.appendChild(leftTitle);
  leftHeader.appendChild(leftRangeInfo);
  leftCol.appendChild(leftHeader);

  // A function without a before range was added by the fix; only file rows
  // (no function) show the whole file.
  if ((!beforeRange && !wholeFile) || typeof beforeText !== 'string' || !beforeText) {
    const emptyNotice = document.createElement('div');
    emptyNotice.style.padding = '16px';
    emptyNotice.style.color = 'var(--text-subtle)';
    emptyNotice.textContent = beforeRange || wholeFile ? '(File not present before this fix)' : '(Function newly added in this fix)';
    leftCol.appendChild(emptyNotice);
  } else {
    const beforeLines = sliceCode(beforeText, beforeRange);
    for (const line of beforeLines) {
      const lineRow = document.createElement('div');
      lineRow.className = 'code-line';
      if (delLines.has(line.num)) {
        lineRow.classList.add('diff-highlight-del');
      }
      const numSpan = document.createElement('span');
      numSpan.className = 'line-number';
      numSpan.textContent = String(line.num);
      const textSpan = document.createElement('span');
      textSpan.className = 'line-content';
      textSpan.textContent = line.text;

      lineRow.appendChild(numSpan);
      lineRow.appendChild(textSpan);
      leftCol.appendChild(lineRow);
    }
  }

  // Right column: After
  const rightCol = document.createElement('div');
  rightCol.className = 'code-column';
  const rightHeader = document.createElement('div');
  rightHeader.className = 'code-col-header';
  const rightTitle = document.createElement('span');
  rightTitle.textContent = `After (${sha ? sha.substring(0, 8) : 'fix'})`;
  const rightRangeInfo = document.createElement('span');
  rightRangeInfo.textContent = afterRange ? `Lines ${afterRange[0]}-${afterRange[1]}` : 'N/A';
  rightHeader.appendChild(rightTitle);
  rightHeader.appendChild(rightRangeInfo);
  rightCol.appendChild(rightHeader);

  if ((!afterRange && !wholeFile) || typeof afterText !== 'string' || !afterText) {
    const emptyNotice = document.createElement('div');
    emptyNotice.style.padding = '16px';
    emptyNotice.style.color = 'var(--text-subtle)';
    emptyNotice.textContent = afterRange || wholeFile ? '(File removed by this fix)' : '(Function removed in this fix)';
    rightCol.appendChild(emptyNotice);
  } else {
    const afterLines = sliceCode(afterText, afterRange);
    for (const line of afterLines) {
      const lineRow = document.createElement('div');
      lineRow.className = 'code-line';
      if (addLines.has(line.num)) {
        lineRow.classList.add('diff-highlight-add');
      }
      const numSpan = document.createElement('span');
      numSpan.className = 'line-number';
      numSpan.textContent = String(line.num);
      const textSpan = document.createElement('span');
      textSpan.className = 'line-content';
      textSpan.textContent = line.text;

      lineRow.appendChild(numSpan);
      lineRow.appendChild(textSpan);
      rightCol.appendChild(lineRow);
    }
  }

  splitView.appendChild(leftCol);
  splitView.appendChild(rightCol);
  container.appendChild(splitView);

  // Patch view (Unified Diff)
  const patchView = document.createElement('div');
  patchView.className = 'patch-view';
  patchView.style.display = 'none';

  if (!patchText) {
    const noDiff = document.createElement('div');
    noDiff.textContent = 'No unified diff patch available.';
    patchView.appendChild(noDiff);
  } else {
    const patchLines = patchText.split('\n');
    for (const pLine of patchLines) {
      const lineDiv = document.createElement('div');
      if (pLine.startsWith('+')) {
        lineDiv.className = 'patch-line-add';
      } else if (pLine.startsWith('-')) {
        lineDiv.className = 'patch-line-del';
      } else if (pLine.startsWith('@@')) {
        lineDiv.className = 'patch-line-hunk';
      }
      lineDiv.textContent = pLine;
      patchView.appendChild(lineDiv);
    }
  }

  container.appendChild(patchView);

  // Tab switching
  sideBySideTab.addEventListener('click', () => {
    sideBySideTab.classList.add('active');
    patchTab.classList.remove('active');
    splitView.style.display = 'grid';
    patchView.style.display = 'none';
  });

  patchTab.addEventListener('click', () => {
    patchTab.classList.add('active');
    sideBySideTab.classList.remove('active');
    splitView.style.display = 'none';
    patchView.style.display = 'block';
  });

  return container;
}
