/**
 * Main application router, UI controller, and view renderer.
 * Vanilla ES module, no external frameworks.
 */

import { getIndex, getCwe, getCve, getSearch } from './data.js';
import { fetchCommit, fetchRawFile, buildCodeViewerElement } from './github.js';
import { renderNeighbourGraph } from './graph.js';

let indexData = null;
let treeMode = 'group'; // 'group' or 'project'

const viewContainer = document.getElementById('view-container');
const navTree = document.getElementById('nav-tree');
const headerTotals = document.getElementById('header-totals');
const searchForm = document.getElementById('search-form');
const searchInput = document.getElementById('search-input');
const treeModeToggle = document.getElementById('tree-mode-toggle');
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebar-toggle');
const sidebarBackdrop = document.getElementById('sidebar-backdrop');

// --- Helper Functions ---

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function closeMobileSidebar() {
  sidebar.classList.remove('open');
  sidebarBackdrop.classList.remove('active');
  sidebarToggle.setAttribute('aria-expanded', 'false');
}

function openMobileSidebar() {
  sidebar.classList.add('open');
  sidebarBackdrop.classList.add('active');
  sidebarToggle.setAttribute('aria-expanded', 'true');
}

// --- App Initialization ---

async function init() {
  // Mobile drawer events
  sidebarToggle.addEventListener('click', () => {
    const isOpen = sidebar.classList.contains('open');
    if (isOpen) closeMobileSidebar();
    else openMobileSidebar();
  });
  sidebarBackdrop.addEventListener('click', closeMobileSidebar);

  // Search form submit
  searchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = searchInput.value.trim();
    if (q) {
      window.location.hash = `#/search?q=${encodeURIComponent(q)}`;
    } else {
      window.location.hash = '#/';
    }
    closeMobileSidebar();
  });

  // Tree mode toggle
  treeModeToggle.addEventListener('click', () => {
    treeMode = treeMode === 'group' ? 'project' : 'group';
    treeModeToggle.textContent = treeMode === 'group' ? 'Group First' : 'Project First';
    renderTree();
  });

  // Hash change routing
  window.addEventListener('hashchange', () => {
    closeMobileSidebar();
    route();
  });

  // Load index data
  try {
    indexData = await getIndex();
    renderHeaderTotals(indexData.totals);
    renderTree();
    route();
  } catch (err) {
    viewContainer.innerHTML = `
      <div class="card">
        <h2 class="card-title">Failed to load Vulnerability Atlas</h2>
        <p style="color: var(--diff-del-text);">${escapeHtml(err.message)}</p>
        <p style="margin-top: 8px; font-size: 0.875rem; color: var(--text-subtle);">
          Build the data with <code>python3 scripts/site/build_site_data.py --out site/data</code>, or pass <code>?data=&lt;path&gt;</code> in the URL.
        </p>
      </div>
    `;
  }
}

// --- Header Totals ---

function renderHeaderTotals(totals) {
  if (!totals) return;
  headerTotals.innerHTML = `
    <span class="total-pill"><strong>${totals.cves.toLocaleString()}</strong> CVEs</span>
    <span class="total-pill"><strong>${totals.projects.toLocaleString()}</strong> Projects</span>
    <span class="total-pill"><strong>${totals.with_fix.toLocaleString()}</strong> Fixed</span>
  `;
}

// --- Sidebar Tree ---

function renderTree() {
  if (!indexData) return;
  navTree.innerHTML = '';
  const rootUl = document.createElement('ul');
  rootUl.className = 'tree-list';

  if (treeMode === 'group') {
    // Mode 1: Group -> CWE -> Project -> CVE
    for (const group of indexData.groups || []) {
      const groupLi = document.createElement('li');
      groupLi.className = 'tree-item';

      const row = document.createElement('div');
      row.className = 'tree-row';

      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'tree-toggle-btn';
      toggleBtn.setAttribute('aria-expanded', 'false');
      toggleBtn.setAttribute('aria-label', `Expand group ${group.name}`);
      toggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

      const label = document.createElement('span');
      label.className = 'tree-label';
      label.textContent = group.name;
      label.addEventListener('click', () => {
        window.location.hash = `#/group/${encodeURIComponent(group.name)}`;
      });

      const count = document.createElement('span');
      count.className = 'tree-count';
      count.textContent = String(group.cves);

      row.appendChild(toggleBtn);
      row.appendChild(label);
      row.appendChild(count);
      groupLi.appendChild(row);

      const nestedUl = document.createElement('ul');
      nestedUl.className = 'tree-nested';
      nestedUl.style.display = 'none';

      toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
        toggleBtn.setAttribute('aria-expanded', String(!expanded));
        nestedUl.style.display = expanded ? 'none' : 'block';

        if (!expanded && nestedUl.children.length === 0) {
          renderGroupCwes(nestedUl, group);
        }
      });

      groupLi.appendChild(nestedUl);
      rootUl.appendChild(groupLi);
    }
  } else {
    // Mode 2: Project -> Group -> CWE -> CVE
    for (const project of indexData.projects || []) {
      const projLi = document.createElement('li');
      projLi.className = 'tree-item';

      const row = document.createElement('div');
      row.className = 'tree-row';

      const toggleBtn = document.createElement('button');
      toggleBtn.className = 'tree-toggle-btn';
      toggleBtn.setAttribute('aria-expanded', 'false');
      toggleBtn.setAttribute('aria-label', `Expand project ${project.name}`);
      toggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

      const label = document.createElement('span');
      label.className = 'tree-label';
      label.textContent = project.name;
      label.addEventListener('click', () => {
        window.location.hash = `#/project/${encodeURIComponent(project.name)}`;
      });

      const count = document.createElement('span');
      count.className = 'tree-count';
      count.textContent = String(project.cves);

      row.appendChild(toggleBtn);
      row.appendChild(label);
      row.appendChild(count);
      projLi.appendChild(row);

      const nestedUl = document.createElement('ul');
      nestedUl.className = 'tree-nested';
      nestedUl.style.display = 'none';

      toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
        toggleBtn.setAttribute('aria-expanded', String(!expanded));
        nestedUl.style.display = expanded ? 'none' : 'block';

        if (!expanded && nestedUl.children.length === 0) {
          renderProjectGroups(nestedUl, project.name);
        }
      });

      projLi.appendChild(nestedUl);
      rootUl.appendChild(projLi);
    }
  }

  navTree.appendChild(rootUl);
}

function renderGroupCwes(containerUl, group) {
  for (const cwe of group.cwes || []) {
    const cweLi = document.createElement('li');
    cweLi.className = 'tree-item';

    const row = document.createElement('div');
    row.className = 'tree-row';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'tree-toggle-btn';
    toggleBtn.setAttribute('aria-expanded', 'false');
    toggleBtn.setAttribute('aria-label', `Expand CWE ${cwe.id}`);
    toggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = `${cwe.id} (${cwe.name})`;
    label.title = `${cwe.id}: ${cwe.name}`;
    label.addEventListener('click', () => {
      window.location.hash = `#/cwe/${encodeURIComponent(cwe.id)}`;
    });

    const count = document.createElement('span');
    count.className = 'tree-count';
    count.textContent = String(cwe.cves);

    row.appendChild(toggleBtn);
    row.appendChild(label);
    row.appendChild(count);
    cweLi.appendChild(row);

    const nestedUl = document.createElement('ul');
    nestedUl.className = 'tree-nested';
    nestedUl.style.display = 'none';

    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      toggleBtn.setAttribute('aria-expanded', String(!expanded));
      nestedUl.style.display = expanded ? 'none' : 'block';

      if (!expanded && nestedUl.children.length === 0) {
        renderCweProjects(nestedUl, cwe);
      }
    });

    cweLi.appendChild(nestedUl);
    containerUl.appendChild(cweLi);
  }
}

function renderCweProjects(containerUl, cwe) {
  const projects = Object.keys(cwe.projects || {});
  for (const projName of projects) {
    const projCount = cwe.projects[projName];
    const projLi = document.createElement('li');
    projLi.className = 'tree-item';

    const row = document.createElement('div');
    row.className = 'tree-row';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'tree-toggle-btn';
    toggleBtn.setAttribute('aria-expanded', 'false');
    toggleBtn.setAttribute('aria-label', `Expand project ${projName} in ${cwe.id}`);
    toggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = projName;
    label.addEventListener('click', () => {
      window.location.hash = `#/project/${encodeURIComponent(projName)}`;
    });

    const count = document.createElement('span');
    count.className = 'tree-count';
    count.textContent = String(projCount);

    row.appendChild(toggleBtn);
    row.appendChild(label);
    row.appendChild(count);
    projLi.appendChild(row);

    const nestedUl = document.createElement('ul');
    nestedUl.className = 'tree-nested';
    nestedUl.style.display = 'none';

    toggleBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      toggleBtn.setAttribute('aria-expanded', String(!expanded));
      nestedUl.style.display = expanded ? 'none' : 'block';

      if (!expanded && nestedUl.children.length === 0) {
        nestedUl.innerHTML = '<li class="tree-item" style="padding: 4px 8px; font-size: 0.75rem; color: var(--text-subtle);">Loading CVEs...</li>';
        try {
          const cweDetail = await getCwe(cwe.id);
          nestedUl.innerHTML = '';
          const cveRows = (cweDetail.rows || []).filter(r => r[1] === projName);
          for (const r of cveRows) {
            const [cveId] = r;
            const cveLi = document.createElement('li');
            cveLi.className = 'tree-item';
            const cveRow = document.createElement('div');
            cveRow.className = 'tree-row';
            const cveLabel = document.createElement('span');
            cveLabel.className = 'tree-label';
            cveLabel.textContent = cveId;
            cveRow.appendChild(cveLabel);
            cveRow.addEventListener('click', () => {
              window.location.hash = `#/cve/${encodeURIComponent(projName)}/${encodeURIComponent(cveId)}`;
            });
            cveLi.appendChild(cveRow);
            nestedUl.appendChild(cveLi);
          }
        } catch (_) {
          nestedUl.innerHTML = '<li class="tree-item" style="padding: 4px 8px; font-size: 0.75rem; color: var(--diff-del-text);">Error loading CVEs</li>';
        }
      }
    });

    projLi.appendChild(nestedUl);
    containerUl.appendChild(projLi);
  }
}

function renderProjectGroups(containerUl, projectName) {
  for (const group of indexData.groups || []) {
    const matchingCwes = (group.cwes || []).filter(c => c.projects && c.projects[projectName]);
    if (matchingCwes.length === 0) continue;

    const groupLi = document.createElement('li');
    groupLi.className = 'tree-item';

    const row = document.createElement('div');
    row.className = 'tree-row';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'tree-toggle-btn';
    toggleBtn.setAttribute('aria-expanded', 'false');
    toggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

    const label = document.createElement('span');
    label.className = 'tree-label';
    label.textContent = group.name;
    label.addEventListener('click', () => {
      window.location.hash = `#/group/${encodeURIComponent(group.name)}`;
    });

    const count = document.createElement('span');
    count.className = 'tree-count';
    const totalProjCves = matchingCwes.reduce((sum, c) => sum + (c.projects[projectName] || 0), 0);
    count.textContent = String(totalProjCves);

    row.appendChild(toggleBtn);
    row.appendChild(label);
    row.appendChild(count);
    groupLi.appendChild(row);

    const nestedUl = document.createElement('ul');
    nestedUl.className = 'tree-nested';
    nestedUl.style.display = 'none';

    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      toggleBtn.setAttribute('aria-expanded', String(!expanded));
      nestedUl.style.display = expanded ? 'none' : 'block';

      if (!expanded && nestedUl.children.length === 0) {
        for (const cwe of matchingCwes) {
          const cweLi = document.createElement('li');
          cweLi.className = 'tree-item';

          const cweRow = document.createElement('div');
          cweRow.className = 'tree-row';

          const cweToggleBtn = document.createElement('button');
          cweToggleBtn.className = 'tree-toggle-btn';
          cweToggleBtn.setAttribute('aria-expanded', 'false');
          cweToggleBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>`;

          const cweLabel = document.createElement('span');
          cweLabel.className = 'tree-label';
          cweLabel.textContent = `${cwe.id}`;
          cweLabel.addEventListener('click', () => {
            window.location.hash = `#/cwe/${encodeURIComponent(cwe.id)}`;
          });

          const cweCount = document.createElement('span');
          cweCount.className = 'tree-count';
          cweCount.textContent = String(cwe.projects[projectName]);

          cweRow.appendChild(cweToggleBtn);
          cweRow.appendChild(cweLabel);
          cweRow.appendChild(cweCount);
          cweLi.appendChild(cweRow);

          const cveUl = document.createElement('ul');
          cveUl.className = 'tree-nested';
          cveUl.style.display = 'none';

          cweToggleBtn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            const cveExpanded = cweToggleBtn.getAttribute('aria-expanded') === 'true';
            cweToggleBtn.setAttribute('aria-expanded', String(!cveExpanded));
            cveUl.style.display = cveExpanded ? 'none' : 'block';

            if (!cveExpanded && cveUl.children.length === 0) {
              cveUl.innerHTML = '<li class="tree-item" style="padding: 4px 8px; font-size: 0.75rem; color: var(--text-subtle);">Loading CVEs...</li>';
              try {
                const cweDetail = await getCwe(cwe.id);
                cveUl.innerHTML = '';
                const cveRows = (cweDetail.rows || []).filter(r => r[1] === projectName);
                for (const r of cveRows) {
                  const [cveId] = r;
                  const itemLi = document.createElement('li');
                  itemLi.className = 'tree-item';
                  const itemRow = document.createElement('div');
                  itemRow.className = 'tree-row';
                  const itemLabel = document.createElement('span');
                  itemLabel.className = 'tree-label';
                  itemLabel.textContent = cveId;
                  itemRow.appendChild(itemLabel);
                  itemRow.addEventListener('click', () => {
                    window.location.hash = `#/cve/${encodeURIComponent(projectName)}/${encodeURIComponent(cveId)}`;
                  });
                  itemLi.appendChild(itemRow);
                  cveUl.appendChild(itemLi);
                }
              } catch (_) {
                cveUl.innerHTML = '<li class="tree-item" style="padding: 4px 8px; font-size: 0.75rem; color: var(--diff-del-text);">Error loading CVEs</li>';
              }
            }
          });

          cweLi.appendChild(cveUl);
          nestedUl.appendChild(cweLi);
        }
      }
    });

    groupLi.appendChild(nestedUl);
    containerUl.appendChild(groupLi);
  }
}

// --- Router ---

async function route() {
  const hash = window.location.hash || '#/';
  viewContainer.innerHTML = '<div class="view-loading"><div class="spinner"></div><p>Loading view...</p></div>';

  try {
    if (hash === '#/' || hash === '#' || hash === '') {
      renderHomeView();
    } else if (hash.startsWith('#/group/')) {
      const name = decodeURIComponent(hash.substring(8));
      renderGroupView(name);
    } else if (hash.startsWith('#/cwe/')) {
      const id = decodeURIComponent(hash.substring(6));
      renderCweView(id);
    } else if (hash.startsWith('#/project/')) {
      const name = decodeURIComponent(hash.substring(10));
      renderProjectView(name);
    } else if (hash.startsWith('#/cve/')) {
      const parts = hash.substring(6).split('/');
      if (parts.length >= 2) {
        const project = decodeURIComponent(parts[0]);
        const id = decodeURIComponent(parts[1]);
        renderCveView(project, id);
      } else {
        renderHomeView();
      }
    } else if (hash.startsWith('#/search')) {
      const qIndex = hash.indexOf('?q=');
      const q = qIndex !== -1 ? decodeURIComponent(hash.substring(qIndex + 3)) : '';
      renderSearchView(q);
    } else {
      renderHomeView();
    }
  } catch (err) {
    viewContainer.innerHTML = `
      <div class="card">
        <h2 class="card-title">Error Loading View</h2>
        <p style="color: var(--diff-del-text);">${escapeHtml(err.message)}</p>
        <p style="margin-top: 12px;"><a href="#/">Return to Home</a></p>
      </div>
    `;
  }
}

// --- View 1: Home ---

function renderHomeView() {
  const { totals, projects, groups } = indexData;

  const cardHtml = `
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value">${totals.cves.toLocaleString()}</div>
        <div class="metric-label">Total Vulnerabilities</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">${totals.projects.toLocaleString()}</div>
        <div class="metric-label">Monitored Projects</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">${totals.with_fix.toLocaleString()}</div>
        <div class="metric-label">With Verified Fix</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">${totals.with_fragments.toLocaleString()}</div>
        <div class="metric-label">With AST Fragments</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">${totals.with_fingerprint.toLocaleString()}</div>
        <div class="metric-label">With Fix Fingerprints</div>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Project Coverage</h2>
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Project</th>
              <th>Repository</th>
              <th>Catalogs</th>
              <th>CVEs</th>
              <th>With Fix</th>
              <th>With Fragments</th>
              <th>With Fingerprint</th>
              <th>Coverage Bar</th>
            </tr>
          </thead>
          <tbody>
            ${projects.map(p => {
              const fixPct = p.cves ? Math.round((p.with_fix / p.cves) * 100) : 0;
              const fragPct = p.cves ? Math.round((p.with_fragments / p.cves) * 100) : 0;
              const fpPct = p.cves ? Math.round((p.with_fingerprint / p.cves) * 100) : 0;
              return `
                <tr>
                  <td><strong><a href="#/project/${encodeURIComponent(p.name)}">${escapeHtml(p.name)}</a></strong></td>
                  <td class="mono"><a href="https://github.com/${escapeHtml(p.repo)}" target="_blank" rel="noopener noreferrer">${escapeHtml(p.repo)}</a></td>
                  <td>${p.catalogs.map(c => `<span class="chip">${escapeHtml(c)}</span>`).join(' ')}</td>
                  <td><strong>${p.cves.toLocaleString()}</strong></td>
                  <td>${p.with_fix.toLocaleString()}</td>
                  <td>${p.with_fragments.toLocaleString()}</td>
                  <td>${p.with_fingerprint.toLocaleString()}</td>
                  <td style="min-width: 140px;">
                    <div class="bar-container" title="Fix: ${fixPct}%, Fragments: ${fragPct}%, Fingerprint: ${fpPct}%">
                      <div class="bar-segment fix" style="width: ${fixPct}%"></div>
                      <div class="bar-segment fragments" style="width: ${fragPct}%"></div>
                      <div class="bar-segment fingerprint" style="width: ${fpPct}%"></div>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">CWE Groups</h2>
      <div class="metrics-grid">
        ${groups.map(g => `
          <div class="metric-card" style="text-align: left; cursor: pointer;" onclick="window.location.hash='#/group/${encodeURIComponent(g.name)}'">
            <div style="display: flex; justify-content: space-between; align-items: baseline;">
              <strong><a href="#/group/${encodeURIComponent(g.name)}">${escapeHtml(g.name)}</a></strong>
              <span class="badge badge-cwe">${g.cves} CVEs</span>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">
              ${(g.cwes || []).map(c => `${escapeHtml(c.id)} (${c.cves})`).slice(0, 3).join(', ')}
              ${(g.cwes || []).length > 3 ? '...' : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <div class="card" style="background: var(--bg-muted);">
      <h3 style="font-size: 0.9375rem; font-weight: 600; margin-bottom: 6px;">How to read this atlas</h3>
      <p style="font-size: 0.875rem; color: var(--text-muted); line-height: 1.6;">
        Every record comes from an official source: the Linux kernel CNA, the curl and OpenSSL advisories, OSV, NVD and CISA Vulnrichment.
        The CWE groups, the "what the fix changed" summaries and the related CVEs are computed by deterministic code from those records and from the fix commits; nothing is written by a language model.
        Source code is fetched live from GitHub in your browser when you open it; this site stores no source code.
      </p>
      ${indexData.cwe_names_notice ? `<p style="font-size: 0.75rem; color: var(--text-subtle); line-height: 1.5; margin-top: 8px;">${escapeHtml(indexData.cwe_names_notice)}</p>` : ''}
    </div>
  `;

  viewContainer.innerHTML = cardHtml;
}

// --- View 2: Group ---

async function renderGroupView(groupName) {
  const group = (indexData.groups || []).find(g => g.name === groupName);
  if (!group) {
    viewContainer.innerHTML = `
      <div class="card">
        <h2 class="card-title">Group Not Found</h2>
        <p>No CWE group named "${escapeHtml(groupName)}" was found in the catalog.</p>
        <p style="margin-top: 12px;"><a href="#/">Return Home</a></p>
      </div>
    `;
    return;
  }

  // Load all CWEs in this group
  const cwePromises = (group.cwes || []).map(c => getCwe(c.id).catch(() => null));
  const cweResults = await Promise.all(cwePromises);

  const allRows = [];
  cweResults.forEach(res => {
    if (res && res.rows) {
      for (const row of res.rows) {
        allRows.push({
          cweId: res.id,
          cweName: res.name,
          id: row[0],
          project: row[1],
          published: row[2],
          hasFix: row[3],
          hasFragments: row[4],
          hasFingerprint: row[5]
        });
      }
    }
  });

  // Sort by published date descending
  allRows.sort((a, b) => (b.published || '').localeCompare(a.published || ''));

  viewContainer.innerHTML = `
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-subtle); font-weight: 600;">CWE Group</span>
          <h1 class="card-title" style="font-size: 1.5rem; margin-bottom: 0;">${escapeHtml(group.name)}</h1>
        </div>
        <span class="badge badge-cwe" style="font-size: 0.875rem;">${group.cves} Total CVEs</span>
      </div>

      <div style="margin-bottom: 20px;">
        <h3 style="font-size: 0.875rem; font-weight: 600; margin-bottom: 8px; color: var(--text-subtle);">CWEs in this group:</h3>
        <div class="chip-list">
          ${(group.cwes || []).map(c => `
            <a href="#/cwe/${encodeURIComponent(c.id)}" class="chip" style="font-size: 0.8125rem; padding: 4px 8px;">
              <strong>${escapeHtml(c.id)}</strong>: ${escapeHtml(c.name)} (${c.cves})
            </a>
          `).join('')}
        </div>
      </div>

      <h3 class="card-title" style="font-size: 1rem;">Vulnerabilities (${allRows.length})</h3>
      <div class="table-wrapper">
        <table class="data-table" id="group-rows-table">
          <thead>
            <tr>
              <th>Advisory ID</th>
              <th>Project</th>
              <th>CWE</th>
              <th>Published</th>
              <th>Fix</th>
              <th>Fragments</th>
              <th>Fingerprint</th>
            </tr>
          </thead>
          <tbody id="group-rows-tbody"></tbody>
        </table>
      </div>
      <div id="group-load-more-container"></div>
    </div>
  `;

  const tbody = document.getElementById('group-rows-tbody');
  const loadMoreContainer = document.getElementById('group-load-more-container');

  renderIncrementalRows(allRows, tbody, loadMoreContainer, (row) => `
    <tr>
      <td class="mono"><strong><a href="#/cve/${encodeURIComponent(row.project)}/${encodeURIComponent(row.id)}">${escapeHtml(row.id)}</a></strong></td>
      <td><a href="#/project/${encodeURIComponent(row.project)}">${escapeHtml(row.project)}</a></td>
      <td><a href="#/cwe/${encodeURIComponent(row.cweId)}">${escapeHtml(row.cweId)}</a></td>
      <td class="mono">${escapeHtml(row.published || 'N/A')}</td>
      <td><span class="status-pill ${row.hasFix ? 'yes' : 'no'}"></span>${row.hasFix ? 'Yes' : 'No'}</td>
      <td><span class="status-pill ${row.hasFragments ? 'yes' : 'no'}"></span>${row.hasFragments ? 'Yes' : 'No'}</td>
      <td><span class="status-pill ${row.hasFingerprint ? 'yes' : 'no'}"></span>${row.hasFingerprint ? 'Yes' : 'No'}</td>
    </tr>
  `);
}

// --- View 3: CWE ---

async function renderCweView(cweId) {
  const cwe = await getCwe(cweId);
  const rows = cwe.rows || [];

  viewContainer.innerHTML = `
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;">
        <div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="badge badge-cwe">${escapeHtml(cwe.id)}</span>
            <a href="#/group/${encodeURIComponent(cwe.group)}" class="badge badge-source">${escapeHtml(cwe.group)}</a>
          </div>
          <h1 class="card-title" style="font-size: 1.5rem; margin-top: 8px; margin-bottom: 0;">${escapeHtml(cwe.name)}</h1>
        </div>
        <span class="tree-count" style="font-size: 0.875rem;">${rows.length} CVEs</span>
      </div>

      <div style="margin-bottom: 16px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap;" id="cwe-filter-bar">
        <span style="font-size: 0.8125rem; font-weight: 600; color: var(--text-subtle);">Filter Project:</span>
        <button class="btn-text btn-sm active" data-proj="all">All (${rows.length})</button>
      </div>

      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Advisory ID</th>
              <th>Project</th>
              <th>Published</th>
              <th>Fix</th>
              <th>Fragments</th>
              <th>Fingerprint</th>
            </tr>
          </thead>
          <tbody id="cwe-rows-tbody"></tbody>
        </table>
      </div>
      <div id="cwe-load-more-container"></div>
    </div>
  `;

  // Build project filters
  const filterBar = document.getElementById('cwe-filter-bar');
  const projCounts = {};
  for (const r of rows) {
    const p = r[1];
    projCounts[p] = (projCounts[p] || 0) + 1;
  }

  for (const p of Object.keys(projCounts)) {
    const btn = document.createElement('button');
    btn.className = 'btn-text btn-sm';
    btn.dataset.proj = p;
    btn.textContent = `${p} (${projCounts[p]})`;
    filterBar.appendChild(btn);
  }

  const tbody = document.getElementById('cwe-rows-tbody');
  const loadMoreContainer = document.getElementById('cwe-load-more-container');

  let currentFilter = 'all';

  function applyFilter() {
    const filteredRows = currentFilter === 'all' ? rows : rows.filter(r => r[1] === currentFilter);
    renderIncrementalRows(filteredRows, tbody, loadMoreContainer, (r) => `
      <tr>
        <td class="mono"><strong><a href="#/cve/${encodeURIComponent(r[1])}/${encodeURIComponent(r[0])}">${escapeHtml(r[0])}</a></strong></td>
        <td><a href="#/project/${encodeURIComponent(r[1])}">${escapeHtml(r[1])}</a></td>
        <td class="mono">${escapeHtml(r[2] || 'N/A')}</td>
        <td><span class="status-pill ${r[3] ? 'yes' : 'no'}"></span>${r[3] ? 'Yes' : 'No'}</td>
        <td><span class="status-pill ${r[4] ? 'yes' : 'no'}"></span>${r[4] ? 'Yes' : 'No'}</td>
        <td><span class="status-pill ${r[5] ? 'yes' : 'no'}"></span>${r[5] ? 'Yes' : 'No'}</td>
      </tr>
    `);
  }

  filterBar.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn || !btn.dataset.proj) return;
    filterBar.querySelectorAll('button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.proj;
    applyFilter();
  });

  applyFilter();
}

// --- View 4: Project ---

async function renderProjectView(projectName) {
  const project = (indexData.projects || []).find(p => p.name === projectName);
  if (!project) {
    viewContainer.innerHTML = `
      <div class="card">
        <h2 class="card-title">Project Not Found</h2>
        <p>No project named "${escapeHtml(projectName)}" was found in the catalog.</p>
        <p style="margin-top: 12px;"><a href="#/">Return Home</a></p>
      </div>
    `;
    return;
  }

  // Find all CWEs that affect this project
  const projectCwes = [];
  for (const group of indexData.groups || []) {
    for (const cwe of group.cwes || []) {
      if (cwe.projects && cwe.projects[projectName]) {
        projectCwes.push({
          id: cwe.id,
          name: cwe.name,
          group: group.name,
          count: cwe.projects[projectName]
        });
      }
    }
  }

  // Load search index to get all CVEs for this project
  const searchItems = await getSearch();
  const projectCves = searchItems.filter(item => item[1] === projectName);

  viewContainer.innerHTML = `
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;">
        <div>
          <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-subtle); font-weight: 600;">Project Catalog</span>
          <h1 class="card-title" style="font-size: 1.5rem; margin-top: 4px; margin-bottom: 4px;">${escapeHtml(project.name)}</h1>
          <div style="font-size: 0.875rem;">
            Repository: <a href="https://github.com/${escapeHtml(project.repo)}" target="_blank" rel="noopener noreferrer" class="mono">${escapeHtml(project.repo)}</a>
          </div>
        </div>
        <div style="display: flex; gap: 6px;">
          ${project.catalogs.map(c => `<span class="chip">${escapeHtml(c)}</span>`).join('')}
        </div>
      </div>

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-value">${project.cves}</div>
          <div class="metric-label">Total CVEs</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">${project.with_fix}</div>
          <div class="metric-label">With Verified Fix</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">${project.with_fragments}</div>
          <div class="metric-label">With AST Fragments</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">${project.with_fingerprint}</div>
          <div class="metric-label">With Fix Fingerprint</div>
        </div>
      </div>

      <h3 class="card-title" style="font-size: 1rem; margin-top: 24px;">CWE Distribution</h3>
      <div class="chip-list" style="margin-bottom: 24px;">
        ${projectCwes.map(c => `
          <a href="#/cwe/${encodeURIComponent(c.id)}" class="chip" style="padding: 4px 8px;">
            <strong>${escapeHtml(c.id)}</strong> (${c.count})
          </a>
        `).join('')}
      </div>

      <h3 class="card-title" style="font-size: 1rem;">Vulnerabilities (${projectCves.length})</h3>
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Advisory ID</th>
              <th>CWE</th>
              <th>Subsystem</th>
              <th>Functions Changed</th>
            </tr>
          </thead>
          <tbody id="project-cves-tbody"></tbody>
        </table>
      </div>
      <div id="project-load-more-container"></div>
    </div>
  `;

  const tbody = document.getElementById('project-cves-tbody');
  const loadMoreContainer = document.getElementById('project-load-more-container');

  renderIncrementalRows(projectCves, tbody, loadMoreContainer, (item) => `
    <tr>
      <td class="mono"><strong><a href="#/cve/${encodeURIComponent(projectName)}/${encodeURIComponent(item[0])}">${escapeHtml(item[0])}</a></strong></td>
      <td>${item[2] ? `<a href="#/cwe/${encodeURIComponent(item[2])}">${escapeHtml(item[2])}</a>` : '<span style="color:var(--text-subtle)">None</span>'}</td>
      <td class="mono">${escapeHtml(item[3] || 'N/A')}</td>
      <td class="mono" style="font-size: 0.75rem;">${escapeHtml(item[4] || '')}</td>
    </tr>
  `);
}

// --- View 5: CVE Detail ---

// Fix fingerprints carry the changed functions' line ranges, so a CVE with a
// fingerprint but no mined fragments still gets the before/after viewer.
function fragmentsFromFingerprint(fp) {
  if (!fp || !fp.functions || fp.functions.length === 0) return null;
  const byPath = new Map();
  for (const fn of fp.functions) {
    if (!byPath.has(fn.path)) {
      byPath.set(fn.path, { path: fn.path, status: 'modified', fix_sha: fp.fix_sha, functions: [] });
    }
    byPath.get(fn.path).functions.push({
      name: fn.name, before_range: fn.before_range || null, after_range: fn.after_range || null,
    });
  }
  return { coverage: 'FINGERPRINT', files: [...byPath.values()] };
}

async function renderCveView(project, cveId) {
  const cve = await getCve(project, cveId);
  if (!cve.fragments && cve.fingerprint) {
    cve.fragments = fragmentsFromFingerprint(cve.fingerprint);
  }

  viewContainer.innerHTML = `
    <div class="card cve-header">
      <div class="cve-title-row">
        <h1 class="cve-id">${escapeHtml(cve.id)}</h1>
        <span class="badge badge-cwe">${escapeHtml(cve.project)}</span>
      </div>

      <div class="cve-meta-tags">
        <a href="#/cwe/${encodeURIComponent(cve.cwe || '')}" class="badge badge-cwe">
          ${escapeHtml(cve.cwe || 'UNKNOWN')}: ${escapeHtml(cve.cwe_name || '')}
        </a>
        <a href="#/group/${encodeURIComponent(cve.group || '')}" class="badge badge-source">
          ${escapeHtml(cve.group || 'Unknown Group')}
        </a>
        <span class="badge badge-source" title="CWE Source Authority">
          source: ${escapeHtml(cve.cwe_source || 'n/a')}
        </span>
        ${cve.subsystem ? `<span class="badge badge-source">subsystem: ${escapeHtml(cve.subsystem)}</span>` : ''}
      </div>

      <div class="meta-grid" style="margin-top: 20px;">
        <div class="meta-item">
          <span class="meta-label">Published Date</span>
          <span class="meta-value mono">${escapeHtml(cve.published || 'Unknown')}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Repository</span>
          <span class="meta-value mono">
            <a href="https://github.com/${escapeHtml(cve.repo)}" target="_blank" rel="noopener noreferrer">${escapeHtml(cve.repo)}</a>
          </span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Catalogs</span>
          <span class="meta-value">${(cve.catalogs || []).map(c => `<span class="chip">${escapeHtml(c)}</span>`).join(' ')}</span>
        </div>
      </div>

      <div class="links-list">
        <span class="meta-label">References & Links</span>
        <div class="link-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
          <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}" target="_blank" rel="noopener noreferrer">
            NVD National Vulnerability Database (${escapeHtml(cve.id)})
          </a>
        </div>
        ${(cve.fixes || []).map(fix => `
          <div class="link-item">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"></circle><line x1="1.05" y1="12" x2="7" y2="12"></line><line x1="17.01" y1="12" x2="22.96" y2="12"></line></svg>
            Fix Commit: <a href="${escapeHtml(fix.url)}" target="_blank" rel="noopener noreferrer" class="mono">${escapeHtml(fix.sha)}</a>
          </div>
        `).join('')}
        ${(cve.patch_urls || []).map(url => `
          <div class="link-item">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            Patch: <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="mono" style="word-break: break-all;">${escapeHtml(url)}</a>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Files & Functions Changed Table -->
    <div class="card">
      <h2 class="card-title">Files and Functions Changed</h2>
      ${renderFragmentsSection(cve)}
    </div>

    <!-- What the Fix Changed (Fingerprint) -->
    <div class="card">
      <h2 class="card-title">What the Fix Changed (AST Fingerprint)</h2>
      ${renderFingerprintSection(cve)}
    </div>

    <!-- Related CVEs & Neighbour Graph -->
    <div class="card">
      <h2 class="card-title">Related Vulnerabilities</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; align-items: start;">
        <div>
          ${renderRelatedList(cve)}
        </div>
        <div>
          <div style="font-size: 0.8125rem; font-weight: 600; color: var(--text-subtle); margin-bottom: 8px;">
            Neighbour Graph
          </div>
          <div id="cve-graph-container" class="graph-container"></div>
        </div>
      </div>
    </div>
  `;

  // Render Neighbour SVG Graph
  const graphContainer = document.getElementById('cve-graph-container');
  if (graphContainer) {
    renderNeighbourGraph(
      graphContainer,
      { id: cve.id, project: cve.project },
      cve.related || [],
      (proj, targetId) => {
        window.location.hash = `#/cve/${encodeURIComponent(proj)}/${encodeURIComponent(targetId)}`;
      }
    );
  }

  // Attach "Show Code" live viewer event handlers
  setupCodeViewerButtons(cve);
}

function renderFragmentsSection(cve) {
  if (!cve.fragments || !cve.fragments.files || cve.fragments.files.length === 0) {
    return `<p style="font-size: 0.875rem; color: var(--text-subtle);">No AST code fragments recorded for this advisory.</p>`;
  }

  return `
    <div class="table-wrapper">
      <table class="data-table">
        <thead>
          <tr>
            <th>File Path</th>
            <th>Language</th>
            <th>Status</th>
            <th>Function</th>
            <th>Before Range</th>
            <th>After Range</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${cve.fragments.files.flatMap((f, fIdx) => {
            const funcs = f.functions && f.functions.length > 0 ? f.functions : [{ name: '(Entire file)', before_range: null, after_range: null }];
            return funcs.map((fn, fnIdx) => {
              const rowId = `fn-row-${fIdx}-${fnIdx}`;
              const viewerContainerId = `viewer-${fIdx}-${fnIdx}`;
              return `
                <tr id="${rowId}">
                  <td class="mono">${escapeHtml(f.path)}</td>
                  <td><span class="chip">${escapeHtml(f.language || '—')}</span></td>
                  <td>${escapeHtml(f.status || 'modified')}</td>
                  <td class="mono"><strong>${escapeHtml(fn.name)}</strong></td>
                  <td class="mono">${fn.before_range ? `${fn.before_range[0]}-${fn.before_range[1]}` : '<span style="color:var(--text-subtle)">N/A</span>'}</td>
                  <td class="mono">${fn.after_range ? `${fn.after_range[0]}-${fn.after_range[1]}` : '<span style="color:var(--text-subtle)">N/A</span>'}</td>
                  <td>
                    <button class="btn-text btn-sm show-code-btn"
                            data-file-idx="${fIdx}"
                            data-fn-idx="${fnIdx}"
                            data-path="${escapeHtml(f.path)}"
                            data-fn-name="${escapeHtml(fn.name)}"
                            data-target="${viewerContainerId}">
                      Show code
                    </button>
                  </td>
                </tr>
                <tr id="${viewerContainerId}-tr" style="display: none;">
                  <td colspan="7" style="padding: 0; background: var(--bg-muted);">
                    <div id="${viewerContainerId}" style="padding: 12px;"></div>
                  </td>
                </tr>
              `;
            });
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function setupCodeViewerButtons(cve) {
  const buttons = viewContainer.querySelectorAll('.show-code-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const fIdx = parseInt(btn.dataset.fileIdx, 10);
      const fnIdx = parseInt(btn.dataset.fnIdx, 10);
      const targetId = btn.dataset.target;
      const targetDiv = document.getElementById(targetId);
      const targetTr = document.getElementById(`${targetId}-tr`);

      if (!targetDiv || !targetTr) return;

      const isOpen = targetTr.style.display !== 'none';
      if (isOpen) {
        targetTr.style.display = 'none';
        btn.textContent = 'Show code';
        return;
      }

      // Open and load if not loaded yet
      targetTr.style.display = 'table-row';
      btn.textContent = 'Hide code';

      if (targetDiv.children.length > 0) {
        return; // already loaded
      }

      targetDiv.innerHTML = '<div style="font-size: 0.8125rem; color: var(--text-muted);"><div class="spinner"></div> Fetching live code from GitHub...</div>';

      const fileObj = cve.fragments.files[fIdx];
      const fnObj = fileObj.functions && fileObj.functions[fnIdx] ? fileObj.functions[fnIdx] : null;

      const fixSha = fileObj.fix_sha || ((cve.fixes && cve.fixes.length > 0) ? cve.fixes[0].sha : null);
      if (!fixSha || !cve.repo) {
        targetDiv.innerHTML = '<div class="rate-limit-box"><p>No Git fix commit or repository specified for live viewer.</p></div>';
        return;
      }

      try {
        // Fetch commit details from GitHub
        const commitData = await fetchCommit(cve.repo, fixSha);
        if (commitData.rateLimited) {
          const el = buildCodeViewerElement({
            repo: cve.repo,
            sha: fixSha,
            rateLimited: true,
            commitUrl: commitData.commitUrl
          });
          targetDiv.innerHTML = '';
          targetDiv.appendChild(el);
          return;
        }

        if (commitData.error) {
          const el = buildCodeViewerElement({
            repo: cve.repo,
            sha: fixSha,
            error: commitData.error,
            commitUrl: commitData.commitUrl
          });
          targetDiv.innerHTML = '';
          targetDiv.appendChild(el);
          return;
        }

        const parentSha = commitData.parentSha;
        const matchedFile = (commitData.files || []).find(f => f.filename === fileObj.path) || { patch: '' };

        // Fetch raw Before and After files
        const beforeTextPromise = parentSha ? fetchRawFile(cve.repo, parentSha, fileObj.path) : Promise.resolve('');
        const afterTextPromise = fetchRawFile(cve.repo, fixSha, fileObj.path);

        const [beforeRes, afterRes] = await Promise.all([beforeTextPromise, afterTextPromise]);

        const beforeText = typeof beforeRes === 'string' ? beforeRes : '';
        const afterText = typeof afterRes === 'string' ? afterRes : '';

        const el = buildCodeViewerElement({
          repo: cve.repo,
          sha: fixSha,
          parentSha,
          filePath: fileObj.path,
          patchText: matchedFile.patch,
          beforeText,
          afterText,
          beforeRange: fnObj ? fnObj.before_range : null,
          afterRange: fnObj ? fnObj.after_range : null,
          rateLimited: (beforeRes && beforeRes.rateLimited) || (afterRes && afterRes.rateLimited),
          commitUrl: commitData.commitUrl
        });

        targetDiv.innerHTML = '';
        targetDiv.appendChild(el);
      } catch (err) {
        targetDiv.innerHTML = `<div class="rate-limit-box"><p>Failed to load code: ${escapeHtml(err.message)}</p></div>`;
      }
    });
  });
}

function renderFingerprintSection(cve) {
  if (!cve.fingerprint || !cve.fingerprint.functions || cve.fingerprint.functions.length === 0) {
    return `<p style="font-size: 0.875rem; color: var(--text-subtle);">No AST fix fingerprint recorded for this advisory.</p>`;
  }

  return `
    <div style="display: flex; flex-direction: column; gap: 16px;">
      ${cve.fingerprint.functions.map(fn => `
        <div style="background: var(--bg-muted); padding: 14px; border-radius: 6px; border: 1px solid var(--border-subtle);">
          <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
            <strong class="mono" style="font-size: 0.9375rem;">${escapeHtml(fn.name)}</strong>
            <span class="mono" style="font-size: 0.75rem; color: var(--text-subtle);">${escapeHtml(fn.path)}</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 0.8125rem;">
            <div>
              <span style="font-weight: 600; color: var(--text-subtle);">Added Guards:</span>
              ${fn.added_guards && fn.added_guards.length > 0 ? `
                <ul style="margin: 4px 0 0 18px;">
                  ${fn.added_guards.map(g => `
                    <li>added a check on <code>${escapeHtml((g.vars || []).join(', ') || 'condition')}</code></li>
                  `).join('')}
                </ul>
              ` : '<span style="color:var(--text-subtle); margin-left: 6px;">None</span>'}
            </div>

            <div>
              <span style="font-weight: 600; color: var(--text-subtle);">Added Calls:</span>
              ${fn.added_calls && fn.added_calls.length > 0 ? `
                <span style="margin-left: 6px;">
                  ${fn.added_calls.map(c => `<code class="chip">${escapeHtml(c)}</code>`).join(' ')}
                </span>
              ` : '<span style="color:var(--text-subtle); margin-left: 6px;">None</span>'}
            </div>

            <div>
              <span style="font-weight: 600; color: var(--text-subtle);">Removed Calls:</span>
              ${fn.removed_calls && fn.removed_calls.length > 0 ? `
                <span style="margin-left: 6px;">
                  ${fn.removed_calls.map(c => `<code class="chip">${escapeHtml(c)}</code>`).join(' ')}
                </span>
              ` : '<span style="color:var(--text-subtle); margin-left: 6px;">None</span>'}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderRelatedList(cve) {
  if (!cve.related || cve.related.length === 0) {
    return `<p style="font-size: 0.875rem; color: var(--text-subtle);">No related vulnerabilities linked to this CVE.</p>`;
  }

  return `
    <div style="display: flex; flex-direction: column; gap: 10px;">
      ${cve.related.map(rel => `
        <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 12px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <a href="#/cve/${encodeURIComponent(rel.project)}/${encodeURIComponent(rel.id)}" class="mono" style="font-weight: 700;">
              ${escapeHtml(rel.id)}
            </a>
            <span class="badge badge-score" title="Relatedness similarity score">
              score: ${(rel.score || 0).toFixed(2)}
            </span>
          </div>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
            Project: <a href="#/project/${encodeURIComponent(rel.project)}">${escapeHtml(rel.project)}</a>
          </div>
          <div class="chip-list" style="margin-top: 6px;">
            ${(rel.shared || []).map(s => `<span class="chip">${escapeHtml(s)}</span>`).join('')}
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

// --- View 6: Search ---

async function renderSearchView(query) {
  searchInput.value = query;
  const items = await getSearch();

  const qLower = query.toLowerCase().trim();
  const tokens = qLower.split(/\s+/).filter(Boolean);

  let results = [];
  if (tokens.length > 0) {
    for (const item of items) {
      const [id, project, cwe, subsystem, funcs] = item;
      const haystack = `${id} ${project} ${cwe || ''} ${subsystem || ''} ${funcs || ''}`.toLowerCase();
      if (tokens.every(t => haystack.includes(t))) {
        results.push(item);
        if (results.length >= 200) break; // limit to 200
      }
    }
  }

  viewContainer.innerHTML = `
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 16px;">
        <h1 class="card-title" style="font-size: 1.5rem; margin-bottom: 0;">
          Search Results: "${escapeHtml(query)}"
        </h1>
        <span class="badge badge-cwe">${results.length} found (max 200)</span>
      </div>

      ${results.length === 0 ? `
        <p style="font-size: 0.875rem; color: var(--text-subtle); padding: 16px 0;">
          No vulnerabilities found matching your search query. Try searching by CVE ID, project, CWE, or function name.
        </p>
      ` : `
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Advisory ID</th>
                <th>Project</th>
                <th>CWE</th>
                <th>Subsystem</th>
                <th>Functions Changed</th>
              </tr>
            </thead>
            <tbody id="search-rows-tbody"></tbody>
          </table>
        </div>
        <div id="search-load-more-container"></div>
      `}
    </div>
  `;

  if (results.length > 0) {
    const tbody = document.getElementById('search-rows-tbody');
    const loadMoreContainer = document.getElementById('search-load-more-container');
    renderIncrementalRows(results, tbody, loadMoreContainer, (item) => `
      <tr>
        <td class="mono"><strong><a href="#/cve/${encodeURIComponent(item[1])}/${encodeURIComponent(item[0])}">${escapeHtml(item[0])}</a></strong></td>
        <td><a href="#/project/${encodeURIComponent(item[1])}">${escapeHtml(item[1])}</a></td>
        <td>${item[2] ? `<a href="#/cwe/${encodeURIComponent(item[2])}">${escapeHtml(item[2])}</a>` : '<span style="color:var(--text-subtle)">None</span>'}</td>
        <td class="mono">${escapeHtml(item[3] || 'N/A')}</td>
        <td class="mono" style="font-size: 0.75rem;">${escapeHtml(item[4] || '')}</td>
      </tr>
    `);
  }
}

// --- Incremental Rendering Helper ---

function renderIncrementalRows(items, tbody, loadMoreContainer, rowRenderer, chunkSize = 100) {
  tbody.innerHTML = '';
  loadMoreContainer.innerHTML = '';

  let renderedCount = 0;

  function renderNextBatch() {
    const batch = items.slice(renderedCount, renderedCount + chunkSize);
    const html = batch.map(rowRenderer).join('');
    tbody.insertAdjacentHTML('beforeend', html);
    renderedCount += batch.length;

    if (renderedCount < items.length) {
      loadMoreContainer.innerHTML = `
        <button class="load-more-btn">
          Show more (${(items.length - renderedCount).toLocaleString()} remaining)
        </button>
      `;
      loadMoreContainer.querySelector('button').addEventListener('click', renderNextBatch);
    } else {
      loadMoreContainer.innerHTML = '';
    }
  }

  renderNextBatch();
}

// Start the app
init();
