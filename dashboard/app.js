// app.js - DevSecOps Correlation & ML Prioritizer Dashboard Logic

// ==========================================================================
// 0. REAL, VERIFIED RESULT DATA (embedded so summary panels are always
//    correct even if the live CSVs aren't served from the expected path)
//    Source: results/feature_importance.csv, cwe_precision_table.csv,
//    ml_evaluation_summary.csv, priority_tier_validation.csv,
//    ml_tier_validation.csv, p3_three_way_comparison.csv
// ==========================================================================
const FEATURE_IMPORTANCE = [
  { feature: 'flagged_by_semgrep', importance: 0.2441 },
  { feature: 'num_tools_agreeing', importance: 0.1754 },
  { feature: 'tfidf: "use"', importance: 0.0965 },
  { feature: 'tfidf: "detected"', importance: 0.0807 },
  { feature: 'flagged_by_sonar', importance: 0.0630 },
  { feature: 'cwe_historical_precision (fold-safe)', importance: 0.0395 },
  { feature: 'tfidf: "instead"', importance: 0.0336 },
  { feature: 'CWE-330 category', importance: 0.0322 },
  { feature: 'tfidf: "java"', importance: 0.0277 },
  { feature: 'tfidf: "going"', importance: 0.0203 }
];

const CWE_NAMES = {
  '89': 'SQL Injection', '330': 'Weak PRNG', '79': 'Cross-Site Scripting',
  '327': 'Broken Crypto Algorithm', '22': 'Path Traversal', '78': 'Command Injection',
  '328': 'Weak Hash', '501': 'Trust Boundary Violation', '90': 'LDAP Injection',
  '614': 'Sensitive Cookie (No Secure Flag)', '643': 'XPath Injection'
};

const CWE_PRECISION = [
  { cwe: '89', tp: 416, fp: 308, total: 724, precision: 0.5746 },
  { cwe: '330', tp: 427, fp: 0, total: 427, precision: 1.0 },
  { cwe: '79', tp: 202, fp: 108, total: 310, precision: 0.6516 },
  { cwe: '327', tp: 256, fp: 27, total: 283, precision: 0.9046 },
  { cwe: '22', tp: 120, fp: 106, total: 226, precision: 0.531 },
  { cwe: '78', tp: 117, fp: 109, total: 226, precision: 0.5177 },
  { cwe: '328', tp: 174, fp: 0, total: 174, precision: 1.0 },
  { cwe: '501', tp: 68, fp: 26, total: 94, precision: 0.7234 },
  { cwe: '90', tp: 26, fp: 28, total: 54, precision: 0.4815 },
  { cwe: '614', tp: 36, fp: 0, total: 36, precision: 1.0 },
  { cwe: '643', tp: 14, fp: 13, total: 27, precision: 0.5185 }
].sort((a, b) => b.precision - a.precision);

const MODEL_SUMMARY = [
  { model: 'Semgrep Alone', precision: 0.6945, recall: 0.8996, f1: 0.7839, auc: null },
  { model: 'SonarQube Alone', precision: 0.7794, recall: 0.4120, f1: 0.5391, auc: null },
  { model: 'Hybrid ML (5-Fold CV)', precision: 0.7069, recall: 0.8551, f1: 0.7731, auc: 0.8406 },
  { model: 'Hybrid ML (P1+P2 Filtered)', precision: 0.8670, recall: 0.4608, f1: 0.6018, auc: 0.8406 }
];

const HEURISTIC_TIER_VALIDATION = [
  { tier: 'P1', tp: 294, fp: 0, total: 294, precision: 1.0 },
  { tier: 'P2', tp: 330, fp: 141, total: 471, precision: 0.7006 },
  { tier: 'P3', tp: 341, fp: 176, total: 517, precision: 0.6596 },
  { tier: 'P4', tp: 528, fp: 366, total: 894, precision: 0.5906 }
];

const ML_TIER_VALIDATION = [
  { tier: 'P1', tp: 473, fp: 0, total: 473, precision: 1.0 },
  { tier: 'P2', tp: 179, fp: 100, total: 279, precision: 0.6416 },
  { tier: 'P3', tp: 607, fp: 440, total: 1047, precision: 0.5798 },
  { tier: 'P4', tp: 156, fp: 785, total: 941, precision: 0.1658 }
];

const LLM_P3_COMPARISON = [
  { approach: 'Rule-Based Baseline (no LLM)', precision: 0.5604, kept: 91, sample: 91, discarded: '-', totalReal: '-', recall: null },
  { approach: 'Anchored Prompt (told scanner claim)', precision: 0.5641, kept: 78, sample: 91, discarded: 7, totalReal: 51, recall: 0.8627 },
  { approach: 'Blind Prompt (raw code only)', precision: 0.5769, kept: 78, sample: 91, discarded: 6, totalReal: 51, recall: 0.8824 }
];

// ==========================================================================
// 1. STATE MANAGEMENT
// ==========================================================================
let allFindings = [];
let filteredFindings = [];
let currentPage = 1;
const rowsPerPage = 15;
let currentSort = { key: 'MLScore', asc: false };
let liveDataLoaded = false; // tracks whether the real per-finding CSV loaded successfully

// ==========================================================================
// 2. CSV PARSER (Robust against quoted strings & commas inside fields)
// ==========================================================================
function parseCSV(text) {
  const lines = text.split(/\r?\n/);
  const result = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    const row = [];
    let insideQuote = false;
    let entry = '';
    
    for (let j = 0; j < line.length; j++) {
      const char = line[j];
      
      if (char === '"') {
        if (insideQuote && line[j + 1] === '"') {
          entry += '"';
          j++; // skip escaped quote
        } else {
          insideQuote = !insideQuote;
        }
      } else if (char === ',' && !insideQuote) {
        row.push(entry.trim());
        entry = '';
      } else {
        entry += char;
      }
    }
    row.push(entry.trim());
    result.push(row);
  }
  return result;
}

// ==========================================================================
// 3. INITIALIZATION & DATA LOADING
// ==========================================================================
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  initNavigation();
  initFilterControls();
  initTableSorting();
  initSimulator();
  initModal();
  initExport();

  await loadRealCSVData();
});

// Load real CSV dataset from results directory
async function loadRealCSVData() {
  const statusBadge = document.querySelector('.badge-status');
  if (statusBadge) statusBadge.innerHTML = `<span class="status-dot"></span><span>Loading dataset...</span>`;

  try {
    // Prefer the location-enriched file (has real file/line, recovered by
    // joining against correlated_findings.csv). Fall back to the plain file
    // if the enrichment step hasn't been run in this environment.
    const candidates = [
      '../results/ml_prioritized_findings_with_location.csv',
      '/results/ml_prioritized_findings_with_location.csv',
      '../results/ml_prioritized_findings.csv',
      '/results/ml_prioritized_findings.csv'
    ];

    let resp = null;
    for (const url of candidates) {
      try {
        const r = await fetch(url);
        if (r.ok) { resp = r; break; }
      } catch (e) { /* try next candidate */ }
    }

    if (resp) {
      const text = await resp.text();
      const rows = parseCSV(text);

      if (rows.length > 1) {
        const header = rows[0].map(h => h.toLowerCase().replace(/[^a-z0-9_]/g, ''));

        const idxTest = header.indexOf('test_name');
        const idxVuln = header.indexOf('real_vulnerability');
        const idxCwe = header.indexOf('cwe');
        const idxSemgrep = header.indexOf('flagged_by_semgrep');
        const idxSonar = header.indexOf('flagged_by_sonar');
        const idxMsg = header.indexOf('message');
        const idxScore = header.indexOf('ml_risk_score');
        const idxPriority = header.indexOf('ml_priority');
        const idxFile = header.indexOf('file');   // only present in the location-enriched file
        const idxLine = header.indexOf('line');

        const parsed = [];
        for (let i = 1; i < rows.length; i++) {
          const row = rows[i];
          if (row.length < 4) continue;

          const testName = row[idxTest] || `BenchmarkTest${String(i).padStart(5, '0')}`;
          const cwe = row[idxCwe] || 'unknown';
          const semgrep = parseInt(row[idxSemgrep]) || 0;
          const sonar = parseInt(row[idxSonar]) || 0;

          let tools = 'None (not flagged by any tool)';
          if (semgrep === 1 && sonar === 1) tools = 'SonarQube, Semgrep';
          else if (sonar === 1) tools = 'SonarQube';
          else if (semgrep === 1) tools = 'Semgrep';

          const rawPriority = row[idxPriority] || '';
          let priority = 'P4';
          if (rawPriority.includes('P1')) priority = 'P1';
          else if (rawPriority.includes('P2')) priority = 'P2';
          else if (rawPriority.includes('P3')) priority = 'P3';
          else if (rawPriority.includes('P4')) priority = 'P4';

          const mlScore = parseFloat(row[idxScore]) || 0.0;
          const isReal = row[idxVuln] === '1' ? 'True' : 'False';
          const msg = row[idxMsg] ? row[idxMsg] : `No message available (test case not flagged by any tool)`;

          // Real file/line when the enriched column exists; otherwise honestly show N/A
          const realFile = idxFile !== -1 && row[idxFile] ? row[idxFile] : null;
          const realLine = idxLine !== -1 && row[idxLine] ? row[idxLine] : null;

          const severity = priority === 'P1' ? 'CRITICAL' : priority === 'P2' ? 'HIGH' : priority === 'P3' ? 'MEDIUM' : 'LOW';

          parsed.push({
            ID: `F-${String(i).padStart(4, '0')}`,
            Tools: tools,
            Test: testName,
            File: realFile || 'N/A (not correlated to a specific source file)',
            Line: realLine || 'N/A',
            CWE: cwe,
            Severity: severity,
            Message: msg,
            Priority: priority,
            MLScore: mlScore,
            GroundTruth: isReal
          });
        }

        if (parsed.length > 0) {
          allFindings = parsed;
          filteredFindings = [...allFindings];
          liveDataLoaded = true;
          sortFindings();
          renderAll();
          if (statusBadge) statusBadge.innerHTML = `<span class="status-dot"></span><span>OWASP Benchmark (${parsed.length.toLocaleString()} Loaded)</span>`;
          return;
        }
      }
    }
  } catch (err) {
    console.warn('Failed to load live CSV, loading demo data fallback', err);
  }

  // Fallback if fetch fails -- table rows are illustrative only; all summary
  // panels (KPIs, feature importance, CWE precision, tier validation, LLM
  // comparison) still use the real embedded numbers above regardless.
  liveDataLoaded = false;
  loadFallbackData();
  if (statusBadge) statusBadge.innerHTML = `<span class="status-dot"></span><span>Demo Table Rows (summary panels use real results)</span>`;
}

function loadFallbackData() {
  // NOTE: this generates illustrative table rows ONLY, used when the live
  // ml_prioritized_findings_with_location.csv can't be fetched (e.g. this
  // dashboard opened via file:// instead of a local server). Every summary
  // panel (KPIs, feature importance, CWE precision, tier validation, LLM
  // comparison) uses the real embedded constants regardless and is NOT
  // affected by this fallback -- only the browsable findings table is.
  const CWE_LIST = Object.keys(CWE_NAMES).map(c => `CWE-${c}`);
  const TOOLS_LIST = ['SonarQube, Semgrep', 'SonarQube', 'Semgrep', 'None (not flagged by any tool)'];
  const fallback = [];

  for (let i = 1; i <= 2740; i++) {
    const cwe = CWE_LIST[i % CWE_LIST.length];
    const tools = TOOLS_LIST[i % TOOLS_LIST.length];
    const isMulti = tools.includes(',');
    const mlScore = isMulti ? +(0.85 + (i % 15) * 0.01).toFixed(2) : +(0.20 + (i % 65) * 0.01).toFixed(2);
    const priority = mlScore >= 0.85 ? 'P1' : mlScore >= 0.65 ? 'P2' : mlScore >= 0.45 ? 'P3' : 'P4';
    const groundTruth = (priority === 'P1' || priority === 'P2') ? 'True' : 'False';

    fallback.push({
      ID: `F-${String(i).padStart(4, '0')}`,
      Tools: tools,
      Test: `BenchmarkTest${String(i).padStart(5, '0')}`,
      File: `[DEMO ROW -- live CSV not found] BenchmarkTest${String(i).padStart(5, '0')}.java`,
      Line: 15 + (i * 7) % 120,
      CWE: cwe,
      Severity: priority === 'P1' ? 'CRITICAL' : priority === 'P2' ? 'HIGH' : priority === 'P3' ? 'MEDIUM' : 'LOW',
      Message: `[Illustrative demo row -- serve this dashboard alongside results/ for live data] ${cwe} finding`,
      Priority: priority,
      MLScore: mlScore,
      GroundTruth: groundTruth
    });
  }

  allFindings = fallback;
  filteredFindings = [...allFindings];
  sortFindings();
  renderAll();
}

// ==========================================================================
// 4. THEME & NAVIGATION
// ==========================================================================
function initTheme() {
  const btn = document.getElementById('themeToggle');
  const savedTheme = localStorage.getItem('theme') || 'light';
  setTheme(savedTheme);

  btn.addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    setTheme(next);
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  const label = document.querySelector('.theme-label');
  if (label) label.textContent = theme === 'dark' ? 'Sea Blue Dark' : 'Beige Light';
}

function initNavigation() {
  const links = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.content-section');

  links.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = link.getAttribute('data-section');

      links.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      sections.forEach(s => {
        s.classList.toggle('active', s.id === target);
      });
    });
  });
}

// ==========================================================================
// 5. FILTER CONTROLS
// ==========================================================================
function initFilterControls() {
  const toolCbs = document.querySelectorAll('input[id^="tool-"]');
  const tierPills = document.querySelectorAll('.tier-pill');
  const cweInput = document.getElementById('cweInput');
  const minScoreSlider = document.getElementById('minScoreSlider');
  const scoreVal = document.getElementById('scoreVal');
  const searchInput = document.getElementById('globalSearch');
  const resetBtn = document.getElementById('resetFilters');
  const tags = document.querySelectorAll('.tag');

  toolCbs.forEach(cb => cb.addEventListener('change', applyFilters));

  tierPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const cb = pill.querySelector('input');
      cb.checked = !cb.checked;
      pill.classList.toggle('active', cb.checked);
      applyFilters();
    });
  });

  cweInput.addEventListener('input', applyFilters);
  searchInput.addEventListener('input', applyFilters);

  minScoreSlider.addEventListener('input', (e) => {
    scoreVal.textContent = parseFloat(e.target.value).toFixed(2);
    applyFilters();
  });

  tags.forEach(tag => {
    tag.addEventListener('click', () => {
      cweInput.value = tag.getAttribute('data-cwe');
      applyFilters();
    });
  });

  resetBtn.addEventListener('click', () => {
    toolCbs.forEach(cb => cb.checked = true);
    tierPills.forEach(pill => {
      const cb = pill.querySelector('input');
      cb.checked = true;
      pill.classList.add('active');
    });
    cweInput.value = '';
    searchInput.value = '';
    minScoreSlider.value = '0.00';
    scoreVal.textContent = '0.00';
    applyFilters();
  });
}

function applyFilters() {
  const activeTools = Array.from(document.querySelectorAll('input[id^="tool-"]:checked')).map(cb => cb.value);
  const activeTiers = Array.from(document.querySelectorAll('.tier-pill input:checked')).map(cb => cb.value);
  const cweQuery = document.getElementById('cweInput').value.trim().toUpperCase();
  const searchQuery = document.getElementById('globalSearch').value.trim().toLowerCase();
  const minScore = parseFloat(document.getElementById('minScoreSlider').value) || 0;

  filteredFindings = allFindings.filter(item => {
    // Tool match
    const toolMatch = activeTools.some(t => item.Tools.includes(t));
    // Tier match
    const tierMatch = activeTiers.includes(item.Priority);
    // CWE match
    const cweMatch = cweQuery ? item.CWE.toUpperCase().includes(cweQuery) : true;
    // Score match
    const scoreMatch = item.MLScore >= minScore;
    // Search match
    const searchMatch = searchQuery ? (
      item.Message.toLowerCase().includes(searchQuery) ||
      item.File.toLowerCase().includes(searchQuery) ||
      item.Test.toLowerCase().includes(searchQuery) ||
      item.CWE.toLowerCase().includes(searchQuery)
    ) : true;

    return toolMatch && tierMatch && cweMatch && scoreMatch && searchMatch;
  });

  currentPage = 1;
  sortFindings();
  renderAll();
}

// Table Sorting
function initTableSorting() {
  const headers = document.querySelectorAll('th.sortable');
  headers.forEach(th => {
    th.addEventListener('click', () => {
      const key = th.getAttribute('data-sort');
      if (currentSort.key === key) {
        currentSort.asc = !currentSort.asc;
      } else {
        currentSort.key = key;
        currentSort.asc = true;
      }
      sortFindings();
      renderTable();
    });
  });
}

function sortFindings() {
  const { key, asc } = currentSort;
  filteredFindings.sort((a, b) => {
    let valA = a[key];
    let valB = b[key];
    if (typeof valA === 'string') valA = valA.toLowerCase();
    if (typeof valB === 'string') valB = valB.toLowerCase();
    if (valA < valB) return asc ? -1 : 1;
    if (valA > valB) return asc ? 1 : -1;
    return 0;
  });
}

// ==========================================================================
// 6. RENDERING FUNCTIONS
// ==========================================================================
function renderAll() {
  renderKPIs();
  renderDonutChart();
  renderTable();
  renderCWEHeatmap();
  renderCWEBars();
  renderFeatureImportance();
  renderTierComparison();
  renderModelSummary();
  renderLLMComparison();
}

function renderKPIs() {
  // The Total Findings / P1 Precision / ROC-AUC / Workload Reduction KPI
  // cards report FIXED, real, verified pipeline-level numbers (from the
  // embedded result constants) -- they intentionally do NOT change when the
  // user applies table filters, since they describe the whole evaluation,
  // not the currently filtered view. The table row count badge DOES update
  // live with filters, since that's genuinely about the visible rows.
  document.getElementById('tableCountBadge').textContent = filteredFindings.length.toLocaleString();
}

function renderFeatureImportance() {
  const container = document.getElementById('featureBarList');
  if (!container) return;

  const maxImportance = FEATURE_IMPORTANCE[0].importance;
  let html = '';
  FEATURE_IMPORTANCE.forEach(f => {
    const pct = (f.importance * 100).toFixed(2);
    const barWidth = (f.importance / maxImportance * 100).toFixed(1);
    html += `
      <div class="feature-item">
        <div class="feature-info">
          <span>${f.feature}</span>
          <span class="feature-percent">${pct}%</span>
        </div>
        <div class="bar-bg"><div class="bar-fill" style="width: ${barWidth}%;"></div></div>
      </div>
    `;
  });
  container.innerHTML = html;
}

function renderTierComparison() {
  const container = document.getElementById('tierComparisonTable');
  if (!container) return;

  let html = `<table class="heatmap-table"><thead><tr>
      <th style="text-align:left;">Tier</th>
      <th>Heuristic Precision</th>
      <th>ML Precision</th>
      <th>Change</th>
    </tr></thead><tbody>`;

  HEURISTIC_TIER_VALIDATION.forEach((h, i) => {
    const m = ML_TIER_VALIDATION[i];
    const diff = (m.precision - h.precision) * 100;
    const diffStr = (diff >= 0 ? '+' : '') + diff.toFixed(1) + ' pp';

    // P4 is a special case: a LOWER real-vulnerability rate here is the
    // desired, positive outcome -- it means the ML model concentrated false
    // positives more effectively into the "safe to deprioritize" tier.
    // For P1-P3, higher precision is straightforwardly better.
    let diffColor, diffNote;
    if (h.tier === 'P4') {
      diffColor = 'var(--sea-primary)';
      diffNote = ' (desired: purer noise bucket)';
    } else {
      diffColor = diff > 2 ? 'var(--sea-primary)' : diff < -2 ? '#C0392B' : 'var(--text-muted)';
      diffNote = '';
    }

    html += `<tr>
      <td style="font-weight:700; text-align:left;">${h.tier}</td>
      <td>${(h.precision * 100).toFixed(1)}% <span style="color:var(--text-muted); font-size:0.75rem;">(n=${h.total})</span></td>
      <td>${(m.precision * 100).toFixed(1)}% <span style="color:var(--text-muted); font-size:0.75rem;">(n=${m.total})</span></td>
      <td style="color:${diffColor}; font-weight:600; font-size:0.85rem;">${diffStr}${diffNote}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderModelSummary() {
  const container = document.getElementById('modelSummaryTable');
  if (!container) return;

  let html = `<table class="heatmap-table"><thead><tr>
      <th style="text-align:left;">Model / Tool</th>
      <th>Precision</th>
      <th>Recall</th>
      <th>F1</th>
      <th>ROC-AUC</th>
    </tr></thead><tbody>`;

  MODEL_SUMMARY.forEach(m => {
    html += `<tr>
      <td style="text-align:left; font-weight:600;">${m.model}</td>
      <td>${(m.precision * 100).toFixed(2)}%</td>
      <td>${(m.recall * 100).toFixed(2)}%</td>
      <td>${m.f1.toFixed(4)}</td>
      <td>${m.auc !== null ? m.auc.toFixed(4) : 'N/A'}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderLLMComparison() {
  const container = document.getElementById('llmComparisonTable');
  if (!container) return;

  let html = `<table class="heatmap-table"><thead><tr>
      <th style="text-align:left;">Approach</th>
      <th>Precision</th>
      <th>Kept</th>
      <th>Real Vulns Discarded</th>
      <th>Recall</th>
    </tr></thead><tbody>`;

  LLM_P3_COMPARISON.forEach(r => {
    html += `<tr>
      <td style="text-align:left; font-weight:600;">${r.approach}</td>
      <td>${(r.precision * 100).toFixed(1)}%</td>
      <td>${r.kept}/${r.sample}</td>
      <td>${r.discarded === '-' ? '&mdash;' : r.discarded + '/' + r.totalReal}</td>
      <td>${r.recall !== null ? (r.recall * 100).toFixed(1) + '%' : '&mdash;'}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderDonutChart() {
  const counts = { P1: 0, P2: 0, P3: 0, P4: 0 };
  filteredFindings.forEach(f => {
    if (counts[f.Priority] !== undefined) counts[f.Priority]++;
  });

  const total = filteredFindings.length || 1;
  const svg = document.getElementById('donutSvg');
  const legend = document.getElementById('donutLegend');
  document.getElementById('donutTotal').textContent = filteredFindings.length.toLocaleString();

  const colors = { P1: '#C0392B', P2: '#D35400', P3: '#006994', P4: '#5D6D7E' };
  let strokeOffset = 0;
  let svgContent = '';
  let legendContent = '';

  Object.keys(counts).forEach(tier => {
    const count = counts[tier];
    const percent = count / total;
    const strokeDash = percent * 283;

    svgContent += `
      <circle cx="50" cy="50" r="45" fill="transparent" 
              stroke="${colors[tier]}" stroke-width="10" 
              stroke-dasharray="${strokeDash} 283" 
              stroke-dashoffset="-${strokeOffset}" />
    `;
    strokeOffset += strokeDash;

    legendContent += `
      <div class="legend-item">
        <span class="legend-color" style="background:${colors[tier]}"></span>
        <span>${tier}: <strong>${count}</strong> (${(percent * 100).toFixed(1)}%)</span>
      </div>
    `;
  });

  svg.innerHTML = svgContent;
  legend.innerHTML = legendContent;
}

function renderTable() {
  const tbody = document.getElementById('tableBody');
  tbody.innerHTML = '';

  const start = (currentPage - 1) * rowsPerPage;
  const end = Math.min(start + rowsPerPage, filteredFindings.length);
  const pageItems = filteredFindings.slice(start, end);

  if (pageItems.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2.5rem; color: var(--text-muted); font-size: 0.95rem;">No matching findings found for current filter selections. Try resetting your search or filter tags.</td></tr>`;
    document.getElementById('paginationInfo').textContent = 'Showing 0 of 0 findings';
    document.getElementById('paginationControls').innerHTML = '';
    return;
  }

  pageItems.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge-tier ${item.Priority}">${item.Priority}</span></td>
      <td class="score-cell">${item.MLScore.toFixed(2)}</td>
      <td class="cwe-cell">${item.CWE}</td>
      <td><strong>${item.Tools}</strong></td>
      <td><code>${item.Test}</code></td>
      <td>${item.Line === 'N/A' ? item.File : item.File + ':' + item.Line}</td>
      <td><span style="font-size:0.75rem; font-weight:600;">${item.Severity}</span></td>
      <td>${item.Message}</td>
    `;
    tr.addEventListener('click', () => openModal(item));
    tbody.appendChild(tr);
  });

  document.getElementById('paginationInfo').textContent = `Showing ${start + 1}-${end} of ${filteredFindings.length} findings`;

  const totalPages = Math.ceil(filteredFindings.length / rowsPerPage);
  const controls = document.getElementById('paginationControls');
  controls.innerHTML = '';

  for (let i = 1; i <= Math.min(totalPages, 8); i++) {
    const btn = document.createElement('button');
    btn.textContent = i;
    if (i === currentPage) btn.classList.add('active');
    btn.addEventListener('click', () => {
      currentPage = i;
      renderTable();
    });
    controls.appendChild(btn);
  }
}

function renderCWEHeatmap() {
  const container = document.getElementById('heatmapContainer');
  const cweMap = {};

  filteredFindings.forEach(f => {
    if (!cweMap[f.CWE]) cweMap[f.CWE] = { P1: 0, P2: 0, P3: 0, P4: 0, total: 0 };
    cweMap[f.CWE][f.Priority]++;
    cweMap[f.CWE].total++;
  });

  let html = `<table class="heatmap-table">
    <thead>
      <tr>
        <th style="text-align:left;">CWE Category</th>
        <th>P1 (Critical)</th>
        <th>P2 (High)</th>
        <th>P3 (Medium)</th>
        <th>P4 (Low)</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>`;

  Object.keys(cweMap).sort().forEach(cwe => {
    const row = cweMap[cwe];
    html += `<tr>
      <td style="font-family:var(--font-mono); font-weight:600; text-align:left;">${cwe}</td>
      <td class="heatmap-cell" style="background:rgba(192, 57, 43, ${Math.min(row.P1 * 0.08, 0.85)});" onclick="filterByCWE('${cwe}')">${row.P1}</td>
      <td class="heatmap-cell" style="background:rgba(211, 84, 0, ${Math.min(row.P2 * 0.08, 0.85)});" onclick="filterByCWE('${cwe}')">${row.P2}</td>
      <td class="heatmap-cell" style="background:rgba(0, 105, 148, ${Math.min(row.P3 * 0.08, 0.85)});" onclick="filterByCWE('${cwe}')">${row.P3}</td>
      <td class="heatmap-cell" style="background:rgba(93, 109, 126, ${Math.min(row.P4 * 0.08, 0.85)});" onclick="filterByCWE('${cwe}')">${row.P4}</td>
      <td style="font-weight:700;">${row.total}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

window.filterByCWE = function(cwe) {
  document.getElementById('cweInput').value = cwe;
  applyFilters();
  document.querySelector('a[data-section="findings"]').click();
};

function renderCWEBars() {
  const container = document.getElementById('cwePrecisionBars');
  if (!container) return;

  let html = `<div style="display:flex; flex-direction:column; gap:0.75rem;">`;
  CWE_PRECISION.forEach(item => {
    const rate = (item.precision * 100).toFixed(1);
    const name = CWE_NAMES[item.cwe] || '';
    const barColor = item.precision >= 0.85 ? 'var(--sea-primary)' : item.precision >= 0.65 ? '#D35400' : '#C0392B';
    html += `
      <div>
        <div style="display:flex; justify-content:space-between; font-size:0.8rem; margin-bottom:0.2rem;">
          <span>CWE-${item.cwe} (${name})</span>
          <span style="font-family:var(--font-mono); font-weight:600; color:${barColor};">${rate}% (n=${item.total})</span>
        </div>
        <div style="height:8px; background:var(--bg-subtle); border-radius:4px; overflow:hidden;">
          <div style="height:100%; width:${rate}%; background:${barColor}; border-radius:4px;"></div>
        </div>
      </div>
    `;
  });
  html += `</div>`;
  container.innerHTML = html;
}

// ==========================================================================
// 7. SIMULATOR & MODAL
// ==========================================================================
function initSimulator() {
  // Removed: the previous version computed precision/hours-saved from an
  // arbitrary formula with no connection to real data. The Threshold
  // Simulator card was replaced with the real Tier Precision comparison
  // (see renderTierComparison) and Model Comparison Summary
  // (see renderModelSummary), both driven by verified result files.
}

function initModal() {
  const modal = document.getElementById('detailModal');
  const closeBtn = document.getElementById('modalClose');

  closeBtn.addEventListener('click', () => modal.classList.remove('active'));
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('active');
  });
}

function openModal(item) {
  const modal = document.getElementById('detailModal');
  const title = document.getElementById('modalTitle');
  const body = document.getElementById('modalBody');

  title.textContent = `${item.Test} - Security Finding Detail`;
  body.innerHTML = `
    <div style="display:flex; gap:0.5rem; margin-bottom:1rem;">
      <span class="badge-tier ${item.Priority}">${item.Priority} Tier</span>
      <span class="badge-status">ML Score: ${item.MLScore.toFixed(2)}</span>
      <span class="badge-status">Ground Truth: ${item.GroundTruth}</span>
    </div>
    <table style="width:100%; border-collapse:collapse; font-size:0.85rem; margin-bottom:1rem;">
      <tr><td style="padding:0.4rem; font-weight:600; width:140px;">CWE Category:</td><td>${item.CWE}</td></tr>
      <tr><td style="padding:0.4rem; font-weight:600;">Detecting Scanners:</td><td>${item.Tools}</td></tr>
      <tr><td style="padding:0.4rem; font-weight:600;">Source File:</td><td><code>${item.File}</code> (Line ${item.Line})</td></tr>
      <tr><td style="padding:0.4rem; font-weight:600;">Severity Level:</td><td>${item.Severity}</td></tr>
    </table>
    <div style="background:var(--bg-subtle); padding:0.8rem; border-radius:6px; font-family:var(--font-mono); font-size:0.8rem;">
      <strong>Scan Finding Message:</strong><br/>
      ${item.Message}
    </div>
  `;

  modal.classList.add('active');
}

// ==========================================================================
// 8. EXPORT
// ==========================================================================
function initExport() {
  document.getElementById('exportBtn').addEventListener('click', () => {
    let csv = 'Priority,MLScore,CWE,Tools,Test,File,Line,Severity,Message,GroundTruth\n';
    filteredFindings.forEach(f => {
      csv += `"${f.Priority}",${f.MLScore},"${f.CWE}","${f.Tools}","${f.Test}","${f.File}",${f.Line},"${f.Severity}","${f.Message.replace(/"/g, '""')}","${f.GroundTruth}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DevSecOps_Correlated_Findings_Export.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  });
}