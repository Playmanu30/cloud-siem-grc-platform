/* Cloud SIEM workspace - vanilla JS, no build step. */

const API = '/api/v1';
const KEY_STORAGE = 'siem.apiKey';
const RECENT_STORAGE = 'siem.recentIocs';
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const view = document.getElementById('view');
const sidebar = document.getElementById('sidebar');
const backdrop = document.getElementById('backdrop');
const menuBtn = document.getElementById('menu-btn');
const drawer = document.getElementById('drawer');
const keyDialog = document.getElementById('key-dialog');
const keyInput = document.getElementById('key-input');
const keyNotice = document.getElementById('key-notice');
const toastEl = document.getElementById('toast');

const state = {
  health: null,
  intelResult: null,
  intelQuery: { type: 'ip', value: '' },
  filters: {
    events: { severity: '', source: '' },
    alerts: { status: 'open', severity: '' },
    compliance: { family: '', status: '' },
  },
  eventsLimit: 50,
  events: [],
  complianceReport: null,
  lastEvent: null,
};

const SCREENS = {
  overview: { label: 'Overview', render: renderOverview },
  alerts: { label: 'Alerts', render: renderAlerts },
  events: { label: 'Events', render: renderEvents },
  intel: { label: 'Threat intel', render: renderIntel },
  compliance: { label: 'Compliance', render: renderCompliance },
  attack: { label: 'ATT&CK', render: renderAttack },
};

let renderSeq = 0;

/* ── Utilities ─────────────────────────────────────────────── */

class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.status = status;
  }
}

const esc = (value) =>
  String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const num = (value) =>
  Number.isFinite(Number(value)) ? new Intl.NumberFormat().format(Number(value)) : '—';

const pad = (n) => String(n).padStart(2, '0');

function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtTime(value) {
  const date = parseDate(value);
  if (!date) return '—';
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function fmtDateTime(value) {
  const date = parseDate(value);
  if (!date) return '—';
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function relTime(value) {
  const date = parseDate(value);
  if (!date) return '—';
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return 'just now';
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function severityChip(severity) {
  const value = SEVERITIES.includes(severity) ? severity : 'info';
  return `<span class="chip chip-${value}">${esc(value)}</span>`;
}

function statusChip(status) {
  const value = String(status || 'unknown').replaceAll(' ', '_');
  const label = String(status || 'unknown').replaceAll('_', ' ');
  return `<span class="chip chip-${esc(value)}">${esc(label)}</span>`;
}

function riskLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'info';
}

function toast(message, { error = false, duration = 4500 } = {}) {
  clearTimeout(toast._timer);
  toastEl.textContent = message;
  toastEl.classList.toggle('error', error);
  toastEl.hidden = false;
  toast._timer = setTimeout(() => {
    toastEl.hidden = true;
  }, duration);
}

function openDialog(dialog) {
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

function closeDialog(dialog) {
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.removeAttribute('open');
}

function isMobileNav() {
  return window.matchMedia('(max-width: 880px)').matches;
}

function setMobileNav(open) {
  sidebar.classList.toggle('open', open);
  backdrop.hidden = !open;
  menuBtn.setAttribute('aria-expanded', String(open));
  document.body.style.overflow = open ? 'hidden' : '';
  if (open) {
    const first = sidebar.querySelector('.nav-item');
    if (first) first.focus();
  }
}

/* ── API client ────────────────────────────────────────────── */

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  const key = localStorage.getItem(KEY_STORAGE);
  if (key) headers['X-API-Key'] = key;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Cannot reach the API. Is the server running?', 0);
  }

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (response.status === 401) {
    openKeyDialog('This API requires a key. Save it to continue.');
    throw new ApiError('Unauthorized. Set the API key.', 401);
  }

  if (!response.ok) {
    let detail = `Request failed (${response.status}).`;
    if (data && typeof data.detail === 'string') detail = data.detail;
    else if (data && Array.isArray(data.detail)) {
      detail = data.detail
        .map((item) => {
          const where = Array.isArray(item.loc) ? item.loc.slice(1).join('.') : '';
          return where ? `${where}: ${item.msg}` : item.msg;
        })
        .join('; ');
    }
    throw new ApiError(detail, response.status);
  }

  return data;
}

async function getHealth() {
  const response = await fetch('/health');
  if (!response.ok) throw new ApiError('Health check failed.', response.status);
  return response.json();
}

async function refreshShell() {
  const env = document.getElementById('scope-env');
  const version = document.getElementById('scope-version');
  const dot = document.getElementById('scope-dot');
  try {
    const health = await getHealth();
    state.health = health;
    env.textContent = health.environment || 'unknown';
    version.textContent = health.version ? `v${health.version}` : '';
    dot.className = `scope-dot ${health.status === 'healthy' ? 'up' : 'down'}`;
  } catch {
    env.textContent = 'offline';
    dot.className = 'scope-dot down';
    return;
  }

  try {
    const dashboard = await api(`${API}/dashboard`);
    const count = dashboard.open_alerts || 0;
    const badge = document.getElementById('nav-alert-count');
    badge.hidden = count === 0;
    badge.textContent = count > 99 ? '99+' : String(count);
  } catch {
    /* the screen will surface the error */
  }
}

/* ── Key dialog ────────────────────────────────────────────── */

function openKeyDialog(message = '') {
  keyInput.value = localStorage.getItem(KEY_STORAGE) || '';
  keyNotice.textContent = message;
  keyNotice.hidden = !message;
  openDialog(keyDialog);
  setTimeout(() => keyInput.focus(), 30);
}

keyDialog.addEventListener('click', (event) => {
  if (event.target === keyDialog) closeDialog(keyDialog);
});
document.getElementById('api-key-btn').addEventListener('click', () => openKeyDialog());
document.querySelectorAll('[data-close-dialog]').forEach((button) => {
  button.addEventListener('click', () => {
    const dialog = document.getElementById(button.dataset.closeDialog);
    if (dialog) closeDialog(dialog);
  });
});
document.getElementById('key-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const value = keyInput.value.trim();
  if (value) localStorage.setItem(KEY_STORAGE, value);
  else localStorage.removeItem(KEY_STORAGE);
  closeDialog(keyDialog);
  toast(value ? 'API key saved for this browser.' : 'Saved API key cleared.');
  refreshShell();
  render({ focus: false });
});
document.getElementById('key-clear').addEventListener('click', () => {
  localStorage.removeItem(KEY_STORAGE);
  keyInput.value = '';
  closeDialog(keyDialog);
  toast('Saved API key cleared.');
  refreshShell();
  render({ focus: false });
});

/* ── Shared UI fragments ───────────────────────────────────── */

function titleRow({ title, subtitle, actions = '', freshness = '' }) {
  return `<header class="title-row">
    <div class="title-copy">
      <h1>${esc(title)}</h1>
      ${subtitle ? `<p class="subtitle">${subtitle}</p>` : ''}
    </div>
    <div class="title-actions">
      ${freshness ? `<span class="freshness" id="freshness">${freshness}</span>` : ''}
      ${actions}
    </div>
  </header>`;
}

function emptyState({ title, text, action = '' }) {
  return `<div class="empty">
    <strong>${esc(title)}</strong>
    <span>${esc(text)}</span>
    ${action}
  </div>`;
}

function errorBlock(error) {
  const message = error instanceof ApiError ? error.message : 'Something went wrong.';
  const action =
    error && error.status === 401
      ? '<button class="btn btn-sm" type="button" data-action="open-key">Set API key</button>'
      : '<button class="btn btn-sm" type="button" data-action="retry">Retry</button>';
  return `<div class="error-block">${esc(message)}<br>${action}</div>`;
}

function skeleton() {
  view.innerHTML = `<div class="skeleton" aria-busy="true" aria-label="Loading">
    <div class="sk-line w-40"></div>
    <div class="sk-line w-60"></div>
    <div class="sk-panel"></div>
    <div class="sk-panel"></div>
  </div>`;
}

function collectButton(label = 'Collect events', variant = 'primary') {
  const className = variant === 'ghost' ? 'btn' : 'btn btn-primary';
  return `<button class="${className}" type="button" data-action="collect">
    <svg class="icon" aria-hidden="true"><use href="#i-collect"/></svg>${esc(label)}
  </button>`;
}

function refreshButton() {
  return `<button class="btn btn-ghost" type="button" data-action="refresh" aria-label="Refresh data">
    <svg class="icon" aria-hidden="true"><use href="#i-refresh"/></svg>Refresh
  </button>`;
}

function selectOptions(values, selected, { all = 'Any' } = {}) {
  return `<option value="">${esc(all)}</option>${values
    .map(
      (value) =>
        `<option value="${esc(value)}"${String(selected) === String(value) ? ' selected' : ''}>${esc(
          String(value).replaceAll('_', ' ')
        )}</option>`
    )
    .join('')}`;
}

/* ── Overview ──────────────────────────────────────────────── */

async function renderOverview() {
  const [dashboard, tactics, eventsData, alertsData, summary, health] = await Promise.all([
    api(`${API}/dashboard`),
    api(`${API}/mitre/tactics`),
    api(`${API}/events?limit=200`),
    api(`${API}/alerts?status=open&limit=100`),
    api(`${API}/compliance/summary`),
    getHealth(),
  ]);

  const events = eventsData.events || [];
  state.events = events;
  const openAlerts = (alertsData.alerts || [])
    .slice()
    .sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))
    .slice(0, 5);
  const criticalHigh = (dashboard.critical_alerts || 0) + (dashboard.high_alerts || 0);
  const services = health.services || {};
  const mappedEvents = (tactics.tactics || []).reduce((sum, item) => sum + item.events_mapped, 0);
  const activeTactics = (tactics.tactics || []).filter((item) => item.events_mapped > 0).length;
  const hasAssessment = typeof summary.compliance_score === 'number';

  let finding;
  if (criticalHigh > 0) {
    const oldest = openAlerts.filter((a) => ['critical', 'high'].includes(a.severity)).at(-1);
    finding = `${criticalHigh} high-priority alert${criticalHigh === 1 ? '' : 's'} open${
      dashboard.critical_alerts ? `, ${dashboard.critical_alerts} critical` : ''
    }${oldest ? `, oldest ${relTime(oldest.created_at)}` : ''}.`;
  } else if (!services.aws_collector || !services.aws_collector.startsWith('configured')) {
    finding =
      services.azure_collector && services.azure_collector.startsWith('configured')
        ? 'Azure is connected, AWS is not. Collection runs with the sources that are configured.'
        : 'No cloud credentials are configured, so collection is idle. Add AWS or Azure read-only credentials to start streaming events.';
  } else if (dashboard.total_events === 0) {
    finding = 'Credentials are configured but no events are stored yet. Run a collection to fetch the last hour.';
  } else {
    finding = `No open alerts. ${num(dashboard.total_events)} events stored, ${num(mappedEvents)} mapped to ATT&CK.`;
  }

  const alertRows = openAlerts
    .map(
      (alert) => `<li class="alert-row">
        ${severityChip(alert.severity)}
        <div class="alert-main">
          <p title="${esc(alert.message)}">${esc(alert.message)}</p>
          <p class="meta">${esc(alert.rule || 'alert')} · ${esc(relTime(alert.created_at))}</p>
        </div>
        <div class="alert-actions">
          <button class="btn btn-ghost btn-sm" type="button" data-action="ack-alert" data-id="${alert.id}">Acknowledge</button>
          <button class="btn btn-ghost btn-sm" type="button" data-action="resolve-alert" data-id="${alert.id}">Resolve</button>
        </div>
      </li>`
    )
    .join('');

  const statuses = summary.status_summary || {};
  const statusCells = [
    ['pass', 'Pass'],
    ['fail', 'Fail'],
    ['warning', 'Warning'],
    ['not_assessed', 'Not assessed'],
  ]
    .map(
      ([key, label]) => `<div class="status-cell">
        <b>${num(statuses[key] || 0)}</b><span>${label}</span>
      </div>`
    )
    .join('');

  const sources = [
    { name: 'AWS', state: services.aws_collector, detail: 'CloudTrail · Security Hub · GuardDuty' },
    { name: 'Azure', state: services.azure_collector, detail: 'Activity Log · Defender alerts' },
    { name: 'Threat intel', state: services.threat_intel, detail: 'VirusTotal · Shodan · AbuseIPDB' },
    {
      name: 'Storage',
      state: services.database,
      detail: `${services.storage || 'sqlite'} · ${num(services.events_stored || 0)} events`,
    },
  ]
    .map((source) => {
      const ok = source.state && (source.state === 'up' || source.state.startsWith('configured'));
      return `<div class="source-row">
        <span class="status-dot ${ok ? 'ok' : 'warn'}" aria-hidden="true"></span>
        <div>
          <div class="source-name">${esc(source.name)}</div>
          <div class="source-meta">${esc(source.detail)}</div>
        </div>
        <span class="source-meta">${ok ? (source.name === 'Storage' ? 'online' : 'connected') : 'not configured'}</span>
      </div>`;
    })
    .join('');

  const recent = events
    .slice(0, 5)
    .map(
      (event, index) => `<li class="event-row" data-action="open-event" data-index="${index}" tabindex="0">
        ${severityChip(event.severity)}
        <div>
          <div class="event-msg" title="${esc(event.message)}">${esc(event.message)}</div>
          <div class="event-meta">${esc(fmtTime(event.timestamp))} · ${esc(event.source)}</div>
        </div>
      </li>`
    )
    .join('');

  const topIps = dashboard.top_source_ips || [];
  const maxIp = Math.max(1, ...topIps.map((item) => item.events));
  const ipRows = topIps
    .map(
      (item) => `<div class="ip-row">
        <span class="ip-addr">${esc(item.ip)}</span>
        <span class="ip-count">${num(item.events)}</span>
        <div class="ip-track" aria-hidden="true"><span style="width:${(item.events / maxIp) * 100}%"></span></div>
      </div>`
    )
    .join('');

  const activity = activityChart(events);
  const firstRun = dashboard.total_events === 0;
  const setupPanel = `<section class="panel" aria-labelledby="start-title">
    <div class="panel-head"><h2 id="start-title">Getting started</h2><span class="meta">first run</span></div>
    <div class="setup-list">
      <div class="setup-row">
        <div><strong>Connect a cloud source</strong><p>Add read-only AWS or Azure credentials to <code>.env</code>, then restart the API.</p></div>
      </div>
      <div class="setup-row">
        <div><strong>Collect events</strong><p>Fetch the last hour of CloudTrail, GuardDuty and Azure activity.</p></div>
        <button class="btn btn-sm" type="button" data-action="collect">Collect</button>
      </div>
      <div class="setup-row">
        <div><strong>Assess compliance</strong><p>Run 25 NIST 800-53 checks; supply a cloud snapshot for a real score.</p></div>
        <button class="btn btn-sm" type="button" data-action="run-assessment">Run</button>
      </div>
      <div class="setup-row">
        <div><strong>Explore ATT&amp;CK</strong><p>See tactic coverage and multi-stage chains once events are mapped.</p></div>
        <a class="text-link" href="#/attack">Open</a>
      </div>
    </div>
    <div class="panel-foot">See QUICK_START.md for credential setup.</div>
  </section>`;

  return `
    ${titleRow({
      title: 'Overview',
      subtitle: esc(finding),
      freshness: `Updated ${fmtTime(new Date().toISOString())}`,
      actions: `${refreshButton()}${collectButton()}`,
    })}

    <section class="kpi-strip" aria-label="Key figures">
      <div class="kpi">
        <div class="kpi-label">Events stored</div>
        <div class="kpi-value">${num(dashboard.total_events)}</div>
        <div class="kpi-sub">${num(events.filter((e) => Date.now() - new Date(e.timestamp).getTime() < 86400000).length)} in the last 24h</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Open alerts</div>
        <div class="kpi-value">${num(dashboard.open_alerts)}</div>
        <div class="kpi-sub">${num(dashboard.critical_alerts)} critical · ${num(dashboard.high_alerts)} high</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Compliance</div>
        <div class="kpi-value">${hasAssessment ? Number(summary.compliance_score).toFixed(1) : '—'}<span class="kpi-unit">${hasAssessment ? '%' : ''}</span></div>
        <div class="kpi-sub">${hasAssessment ? `${num(summary.total_controls)} NIST controls` : 'no assessment yet'}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Mapped events</div>
        <div class="kpi-value">${num(mappedEvents)}</div>
        <div class="kpi-sub">${activeTactics} of 12 tactics observed</div>
      </div>
    </section>

    <div class="grid grid-main">
      <div class="stack">
        <section class="panel" aria-labelledby="attention-title">
          <div class="panel-head">
            <div>
              <h2 id="attention-title">Needs attention</h2>
              <p class="meta">${num(dashboard.open_alerts)} open alert${dashboard.open_alerts === 1 ? '' : 's'}</p>
            </div>
            <a class="text-link" href="#/alerts">View all</a>
          </div>
          ${alertRows
            ? `<ul class="alert-list">${alertRows}</ul>`
            : emptyState({
                title: 'No open alerts',
                text: 'High and critical events create alerts when they are collected.',
                action: collectButton('Collect events', 'ghost'),
              })}
        </section>

        ${
          firstRun
            ? setupPanel
            : `<section class="panel" aria-labelledby="ip-title">
                <div class="panel-head">
                  <h2 id="ip-title">Top source IPs</h2>
                  <span class="meta">most active in stored events</span>
                </div>
                ${ipRows || emptyState({ title: 'No source IPs yet', text: 'CloudTrail events carry a source address once collected.' })}
              </section>`
        }
      </div>

      <div class="stack">
        <section class="panel" aria-labelledby="compliance-title">
          <div class="panel-head">
            <h2 id="compliance-title">Compliance</h2>
            <a class="text-link" href="#/compliance">Details</a>
          </div>
          <div class="panel-body">
            <div class="compliance-figure">
              <strong>${hasAssessment ? Number(summary.compliance_score).toFixed(1) : '—'}</strong>
              <span>${hasAssessment ? '% of NIST 800-53 controls passing' : 'no assessment yet'}</span>
            </div>
            <div class="meter" aria-hidden="true"><span style="width:${hasAssessment ? Math.max(0, Math.min(100, summary.compliance_score)) : 0}%"></span></div>
            <div class="status-grid">${statusCells}</div>
            <button class="btn btn-sm" type="button" data-action="run-assessment">Run assessment</button>
          </div>
        </section>

        <section class="panel" aria-labelledby="sources-title">
          <div class="panel-head">
            <h2 id="sources-title">Sources</h2>
            <span class="meta">integration state</span>
          </div>
          <div class="source-list">${sources}</div>
        </section>
      </div>
    </div>

    <div class="grid grid-main section">
      <section class="panel activity" aria-labelledby="activity-title">
        <div class="panel-head">
          <div>
            <h2 id="activity-title">Event activity</h2>
            <p class="meta">Stored events by local hour, last 24 hours</p>
          </div>
          <a class="text-link" href="#/events">Open events</a>
        </div>
        <div class="panel-body">${activity.svg}</div>
        ${activity.peakText ? `<div class="panel-foot">${activity.peakText}</div>` : ''}
      </section>

      <section class="panel" aria-labelledby="recent-title">
        <div class="panel-head">
          <h2 id="recent-title">Recent events</h2>
          <a class="text-link" href="#/events">View all</a>
        </div>
        ${
          recent
            ? `<ul class="event-feed">${recent}</ul>`
            : `${emptyState({
                title: 'No events stored',
                text: 'Collected CloudTrail, GuardDuty and Azure events appear here.',
                action: collectButton('Collect events', 'ghost'),
              })}<div class="panel-foot">Events are stored in SQLite and survive restarts.</div>`
        }
      </section>
    </div>`;
}

function activityChart(events) {
  const now = Date.now();
  const buckets = new Array(24).fill(0);
  let total = 0;
  events.forEach((event) => {
    const date = parseDate(event.timestamp);
    if (!date) return;
    const age = now - date.getTime();
    if (age < 0 || age > 86400000) return;
    buckets[date.getHours()] += 1;
    total += 1;
  });

  const max = Math.max(1, ...buckets);
  if (total === 0) {
    return {
      svg: `<svg viewBox="0 0 520 90" role="img" aria-label="No events in the last 24 hours">
        <line class="baseline" x1="34" y1="60" x2="508" y2="60"/>
        <text class="empty-chart" x="271" y="34" text-anchor="middle">No events in the last 24 hours</text>
      </svg>`,
      peakText: '',
    };
  }
  const plot = { x: 34, y: 12, w: 474, h: 102 };
  const barW = 15;
  const step = plot.w / 24;
  const bars = buckets
    .map((count, hour) => {
      const height = count === 0 ? 0 : Math.max(2, (count / max) * (plot.h - 8));
      const x = plot.x + hour * step + (step - barW) / 2;
      const y = plot.y + plot.h - height;
      return `<rect class="bar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW}" height="${height.toFixed(
        1
      )}" rx="1"><title>${pad(hour)}:00, ${count} event${count === 1 ? '' : 's'}</title></rect>`;
    })
    .join('');

  const labels = [0, 6, 12, 18, 23]
    .map((hour) => `<text class="axis-label" x="${(plot.x + hour * step + step / 2).toFixed(1)}" y="136" text-anchor="middle">${pad(hour)}</text>`)
    .join('');

  const peakHour = buckets.indexOf(max);
  const peakText = total
    ? `Peak ${pad(peakHour)}:00 · ${num(max)} event${max === 1 ? '' : 's'} in an hour`
    : 'No activity in the window';

  const svg = `<svg viewBox="0 0 520 150" role="img" aria-label="Event activity in the last 24 hours: ${total} events">
    <text class="axis-label" x="0" y="18">${max}</text>
    <text class="axis-label" x="0" y="116">0</text>
    <line class="baseline" x1="${plot.x}" y1="${plot.y + plot.h}" x2="${plot.x + plot.w}" y2="${plot.y + plot.h}"/>
    ${bars}
    ${labels}
  </svg>`;

  return { svg, peakText };
}

/* ── Alerts ────────────────────────────────────────────────── */

async function renderAlerts() {
  const filters = state.filters.alerts;
  const [data, dashboard] = await Promise.all([
    api(`${API}/alerts?limit=200`),
    api(`${API}/dashboard`),
  ]);
  const all = data.alerts || [];
  const alerts = all
    .filter(
      (alert) =>
        (!filters.status || alert.status === filters.status) &&
        (!filters.severity || alert.severity === filters.severity)
    )
    .sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) ||
        new Date(b.created_at) - new Date(a.created_at)
    );
  const closed = all
    .filter((alert) => alert.status !== 'open')
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 4);

  const rows = alerts
    .map(
      (alert) => `<tr>
        <td data-label="Severity">${severityChip(alert.severity)}</td>
        <td class="cell-primary" data-label="">${esc(alert.message)}
          <div class="sub">${esc(alert.rule || 'alert')}${alert.event_id ? ` · event #${alert.event_id}` : ''}</div>
        </td>
        <td data-label="Status">${statusChip(alert.status)}</td>
        <td data-label="Created" class="mono nowrap">${esc(fmtDateTime(alert.created_at))}</td>
        <td class="cell-actions">
          ${
            alert.status === 'open'
              ? `<button class="btn btn-ghost btn-sm" type="button" data-action="ack-alert" data-id="${alert.id}">Acknowledge</button>
                 <button class="btn btn-ghost btn-sm" type="button" data-action="resolve-alert" data-id="${alert.id}">Resolve</button>`
              : alert.status === 'acknowledged'
                ? `<button class="btn btn-ghost btn-sm" type="button" data-action="resolve-alert" data-id="${alert.id}">Resolve</button>`
                : '<span class="muted small">closed</span>'
          }
        </td>
      </tr>`
    )
    .join('');

  const closedRows = closed
    .map(
      (alert) => `<li class="alert-row">
        ${statusChip(alert.status)}
        <div class="alert-main">
          <p title="${esc(alert.message)}">${esc(alert.message)}</p>
          <p class="meta">${esc(alert.rule || 'alert')} · closed ${esc(relTime(alert.created_at))}</p>
        </div>
        <span class="muted small mono">${esc(fmtDateTime(alert.created_at))}</span>
      </li>`
    )
    .join('');

  return `
    ${titleRow({
      title: 'Alerts',
      subtitle: `${num(dashboard.open_alerts)} open · ${num(alerts.length)} in this view. High and critical collected events create alerts; duplicates inside an hour are merged.`,
      actions: refreshButton(),
    })}
    <div class="filter-row" data-filters="alerts" data-auto>
      <label class="field inline"><span>Status</span>
        <select name="status">${selectOptions(['open', 'acknowledged', 'resolved'], filters.status, { all: 'All' })}</select>
      </label>
      <label class="field inline"><span>Severity</span>
        <select name="severity">${selectOptions(SEVERITIES, filters.severity)}</select>
      </label>
    </div>
    <section class="panel">
      ${
        rows
          ? `<div class="table-wrap"><table class="table">
              <thead><tr><th>Severity</th><th>Alert</th><th>Status</th><th>Created</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table></div>`
          : emptyState({
              title: 'No alerts in this view',
              text: filters.status === 'open' ? 'Nothing is waiting for triage.' : 'Try another status or collect new events.',
              action: collectButton('Collect events', 'ghost'),
            })
      }
    </section>
    <section class="panel section">
      <div class="panel-head">
        <h2>Recently closed</h2>
        <span class="meta">acknowledged and resolved</span>
      </div>
      ${
        closedRows
          ? `<ul class="alert-list">${closedRows}</ul>`
          : emptyState({
              title: 'Nothing closed yet',
              text: 'Acknowledged and resolved alerts stay here for context.',
            })
      }
    </section>`;
}

/* ── Events ────────────────────────────────────────────────── */

async function renderEvents() {
  const filters = state.filters.events;
  const query = new URLSearchParams();
  query.set('limit', String(state.eventsLimit));
  if (filters.severity) query.set('severity', filters.severity);
  if (filters.source) query.set('source', filters.source);

  const data = await api(`${API}/events?${query}`);
  state.events = data.events || [];

  const rows = state.events
    .map(
      (event, index) => `<tr data-action="open-event" data-index="${index}" tabindex="0">
        <td data-label="Time" class="mono nowrap">${esc(fmtDateTime(event.timestamp))}</td>
        <td data-label="Severity">${severityChip(event.severity)}</td>
        <td data-label="Source" class="muted">${esc(event.source)}</td>
        <td class="cell-primary">${esc(event.message)}
          <div class="sub">${esc(event.event_type)}${
            event.details && event.details.mitre
              ? ` · ${esc(event.details.mitre.technique_id)} ${esc(event.details.mitre.technique_name)}`
              : ''
          }</div>
        </td>
        <td class="cell-actions chevron-cell"><svg class="icon muted" aria-hidden="true"><use href="#i-chevron"/></svg></td>
      </tr>`
    )
    .join('');

  const more = state.events.length < data.total;

  return `
    ${titleRow({
      title: 'Events',
      subtitle: `${num(data.total)} stored security events. Click a row for the normalized record and its ATT&CK mapping.`,
      actions: `${refreshButton()}${collectButton()}`,
    })}
    <form class="filter-row" data-filters="events">
      <label class="field inline"><span>Severity</span>
        <select name="severity">${selectOptions(SEVERITIES, filters.severity)}</select>
      </label>
      <label class="field grow"><span>Source (exact)</span>
        <input type="text" name="source" value="${esc(filters.source)}" placeholder="e.g. AWS CloudTrail" list="event-sources">
        <datalist id="event-sources">
          <option value="AWS CloudTrail"></option><option value="AWS Security Hub"></option>
          <option value="AWS GuardDuty"></option><option value="Azure Activity Log"></option>
          <option value="Microsoft Defender for Cloud"></option>
        </datalist>
      </label>
      <button class="btn" type="submit">Apply</button>
      ${filters.severity || filters.source ? '<button class="btn btn-ghost" type="button" data-action="clear-event-filters">Clear</button>' : ''}
    </form>
    <section class="panel">
      ${
        rows
          ? `<div class="table-wrap"><table class="table">
              <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Event</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table></div>
            <div class="panel-foot">Showing ${num(state.events.length)} of ${num(data.total)}${
              more
                ? ` · <button class="btn btn-ghost btn-sm" type="button" data-action="load-more">Load 50 more</button>`
                : ''
            }</div>`
          : emptyState({
              title: 'No events match',
              text: 'Collect from AWS or Azure, or clear the filters.',
              action: collectButton('Collect events', 'ghost'),
            })
      }
    </section>`;
}

function openEventDrawer(index) {
  const event = state.events[index];
  if (!event) return;
  state.lastEvent = event;
  const mitre = event.details && event.details.mitre;
  document.getElementById('drawer-title').textContent = event.event_type;
  document.getElementById('drawer-sub').textContent = `${event.source} · ${fmtDateTime(event.timestamp)}`;

  const detail = event.details || {};
  const facts = [
    ['Severity', severityChip(event.severity)],
    ['Stored at', esc(event.timestamp)],
    ['Source IP', esc(detail.source_ip || '—')],
    ['User', esc(detail.user_name || '—')],
    ['Account', esc(detail.account_id || '—')],
    ['Region', esc(detail.region || '—')],
  ]
    .map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`)
    .join('');

  const mitreBlock = mitre
    ? `<div class="detail-section">
        <h3>ATT&amp;CK</h3>
        <dl class="detail-meta">
          <div><dt>Technique</dt><dd>${esc(mitre.technique_id)} · ${esc(mitre.technique_name)}</dd></div>
          <div><dt>Tactic</dt><dd>${esc(mitre.tactic_id)} · ${esc(mitre.tactic_name)}</dd></div>
        </dl>
      </div>`
    : '';

  document.getElementById('drawer-body').innerHTML = `
    <dl class="detail-meta">${facts}</dl>
    ${mitreBlock}
    <div class="detail-section">
      <h3>Details</h3>
      <pre class="code">${esc(JSON.stringify(detail, null, 2))}</pre>
    </div>
    <div class="dialog-actions">
      <button class="btn btn-ghost" type="button" data-action="copy-event">Copy JSON</button>
      <button class="btn" type="button" data-close-dialog="drawer">Close</button>
    </div>`;
  document.querySelectorAll('#drawer [data-close-dialog]').forEach((button) => {
    button.addEventListener('click', () => closeDialog(drawer));
  });
  openDialog(drawer);
}

/* ── Threat intel ──────────────────────────────────────────── */

async function renderIntel() {
  const health = await getHealth();
  const configured = (health.services && health.services.threat_intel) === 'configured';
  const result = state.intelResult;
  const recent = recentIocs();

  const recentBlock = recent.length
    ? `<div class="recent-iocs">${recent
        .map(
          (item) => `<button type="button" data-action="recent-ioc" data-type="${esc(item.type)}" data-value="${esc(item.value)}">
            <span class="mono">${esc(item.type)}</span>
            <span>${esc(item.value)}</span>
            <span class="mono">${esc(item.score)}</span>
          </button>`
        )
        .join('')}</div>`
    : '<p class="muted small">Lookups you run are kept in this browser for quick reuse.</p>';

  return `
    ${titleRow({
      title: 'Threat intel',
      subtitle: 'Enrich an IP, file hash or domain with VirusTotal, Shodan and AbuseIPDB. Results are cached for 24 hours.',
      actions: refreshButton(),
    })}
    ${configured ? '' : '<p class="notice">No threat-intelligence keys are configured. Add <code>VT_API_KEY</code>, <code>SHODAN_API_KEY</code> or <code>ABUSEIPDB_API_KEY</code> to <code>.env</code> and restart the API.</p>'}
    <div class="intel-grid section">
      <div class="stack">
        <section class="panel">
          <div class="panel-head"><h2>Look up an indicator</h2></div>
          <div class="panel-body">
            <form class="intel-form" id="intel-form">
              <label class="field"><span>Type</span>
                <select name="type" ${configured ? '' : 'disabled'}>
                  <option value="ip"${state.intelQuery.type === 'ip' ? ' selected' : ''}>IP address</option>
                  <option value="hash"${state.intelQuery.type === 'hash' ? ' selected' : ''}>File hash</option>
                  <option value="domain"${state.intelQuery.type === 'domain' ? ' selected' : ''}>Domain</option>
                </select>
              </label>
              <label class="field"><span>Value</span>
                <input type="text" name="value" value="${esc(state.intelQuery.value)}" placeholder="${state.intelQuery.type === 'ip' ? '185.220.101.34' : state.intelQuery.type === 'hash' ? '44d88612fea8a8f36de82e1278abb02f' : 'secure-update.net'}" ${configured ? '' : 'disabled'} maxlength="2048" required>
              </label>
              <button class="btn btn-primary" type="submit" ${configured ? '' : 'disabled'}>Look up</button>
            </form>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head"><h2>Recent lookups</h2><span class="meta">this browser</span></div>
          <div class="panel-body tight">${recentBlock}</div>
        </section>
      </div>

      <div class="stack">
        <section class="panel">
          <div class="panel-head"><h2>Result</h2>${result ? `<span class="meta">${esc(state.intelQuery.type)}</span>` : ''}</div>
          <div class="panel-body">
            ${
              result
                ? intelResultTemplate(result)
                : emptyState({
                    title: 'Nothing looked up yet',
                    text: configured
                      ? 'A lookup combines every configured source into one risk score.'
                      : 'Configure at least one threat-intelligence key to enable lookups.',
                  })
            }
          </div>
        </section>

        <section class="panel">
          <div class="panel-head"><h2>How the score is built</h2></div>
          <div class="panel-body">
            <dl class="detail-meta" style="margin-bottom:0">
              <div><dt>Aggregate</dt><dd>Mean of the source scores that returned data</dd></div>
              <div><dt>Risk level</dt><dd>Set by the highest source score</dd></div>
              <div><dt>Coverage</dt><dd>VirusTotal: IP, hash, domain · Shodan / AbuseIPDB: IP</dd></div>
              <div><dt>Limits</dt><dd>24h cache · VirusTotal 4 requests/minute</dd></div>
            </dl>
          </div>
        </section>
      </div>
    </div>`;
}

function intelResultTemplate(result) {
  const sources = result.sources || {};
  const topScore = Math.max(
    Number(result.aggregate_risk_score || 0),
    Number(result.max_risk_score || 0),
    Number(result.risk_score || 0)
  );
  const level = result.risk_level || riskLevel(topScore);

  const cards = Object.entries(sources)
    .map(([name, source]) => {
      if (!source || typeof source !== 'object') return '';
      if (source.error) {
        return `<div class="source-card"><h3>${esc(name)}</h3><p class="muted small">${esc(source.error)}</p></div>`;
      }
      const fields = [];
      const add = (label, value) => {
        if (value === undefined || value === null || value === '') return;
        fields.push([label, value]);
      };
      if (name === 'virustotal') {
        add('Malicious', source.malicious_count);
        add('Suspicious', source.suspicious_count);
        add('Harmless', source.harmless_count);
        add('Reputation', source.reputation);
        add('Country', source.country);
        add('File', source.file_name);
      } else if (name === 'shodan') {
        add('Open ports', Array.isArray(source.open_ports) ? source.open_ports.join(', ') : source.open_ports);
        add('Vulnerabilities', Array.isArray(source.vulns) ? source.vulns.length : source.vulns);
        add('Organisation', source.organization);
        add('OS', source.os);
      } else if (name === 'abuseipdb') {
        add('Confidence', source.abuse_confidence_score);
        add('Reports', source.total_reports);
        add('Distinct users', source.num_distinct_users);
        add('TOR', source.is_tor ? 'yes' : 'no');
        add('Usage', source.usage_type);
      } else {
        add('Risk score', source.risk_score);
      }
      const rows = fields
        .map(([label, value]) => `<div class="kv"><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`)
        .join('');
      return `<div class="source-card"><h3>${esc(name)}</h3><dl>${rows}</dl></div>`;
    })
    .join('');

  const ioc = result.ioc || {};
  return `
    <div class="risk-head">
      <div>
        <p class="muted small">${esc(ioc.value || result.ip || result.domain || result.hash || '')}</p>
        <div class="risk-score"><strong>${num(topScore)}</strong><span>/100 · ${esc(level)}</span></div>
      </div>
      ${severityChip(level)}
    </div>
    <div class="source-results">
      ${cards || '<p class="muted small">No source returned data.</p>'}
    </div>
    <div class="detail-section" style="margin-top:16px">
      <h3>Raw response</h3>
      <pre class="code">${esc(JSON.stringify(result, null, 2))}</pre>
    </div>`;
}

function recentIocs() {
  try {
    const parsed = JSON.parse(localStorage.getItem(RECENT_STORAGE) || '[]');
    return Array.isArray(parsed) ? parsed.slice(0, 5) : [];
  } catch {
    return [];
  }
}

function pushRecent(entry) {
  const list = recentIocs().filter((item) => !(item.type === entry.type && item.value === entry.value));
  list.unshift(entry);
  localStorage.setItem(RECENT_STORAGE, JSON.stringify(list.slice(0, 5)));
}

async function lookupIoc(type, value) {
  state.intelQuery = { type, value };
  const result = await api(`${API}/threat-intel/enrich`, {
    method: 'POST',
    body: { type, value },
  });
  state.intelResult = result;
  const score = Math.max(
    Number(result.aggregate_risk_score || 0),
    Number(result.max_risk_score || 0),
    Number(result.risk_score || 0)
  );
  pushRecent({ type, value, score, at: new Date().toISOString() });
  return result;
}

/* ── Compliance ────────────────────────────────────────────── */

async function renderCompliance() {
  const [summary, reports, reportResponse] = await Promise.all([
    api(`${API}/compliance/summary`),
    api(`${API}/compliance/reports?limit=5`),
    api(`${API}/compliance/report/latest`).catch((error) => {
      if (error.status === 404) return null;
      throw error;
    }),
  ]);

  state.complianceReport = reportResponse;
  const report = reportResponse;
  const controls = (report && report.controls) || [];
  const families = [...new Set(controls.map((control) => control.family))].sort();
  const filters = state.filters.compliance;
  const visible = controls.filter(
    (control) =>
      (!filters.family || control.family === filters.family) &&
      (!filters.status || control.status === filters.status)
  );
  const statuses = (report && report.status_summary) || summary.status_summary || {};
  const scored = typeof summary.compliance_score === 'number';
  const dataSources = (report && report.data_sources) || summary.data_sources || {};
  const noData = unifiedNoData(dataSources);

  const statusCells = [
    ['pass', 'Pass'],
    ['fail', 'Fail'],
    ['warning', 'Warning'],
    ['not_assessed', 'Not assessed'],
  ]
    .map(
      ([key, label]) => `<div class="status-cell"><b>${num(statuses[key] || 0)}</b><span>${label}</span></div>`
    )
    .join('');

  const controlRows = visible
    .map(
      (control) => `<tr>
        <td data-label="Control" class="mono nowrap">${esc(control.control_id)}</td>
        <td class="cell-primary" data-label="">${esc(control.title)}
          <div class="sub">${esc(control.family)}</div>
        </td>
        <td data-label="Status">${statusChip(control.status)}</td>
        <td data-label="Findings" class="muted">${
          control.findings && control.findings.length
            ? esc(control.findings.slice(0, 2).join(' · '))
            : '—'
        }</td>
      </tr>`
    )
    .join('');

  const historyRows = (reports.reports || [])
    .map(
      (item) => `<div class="source-row">
        <span class="status-dot ok" aria-hidden="true"></span>
        <div>
          <div class="source-name mono">${esc(fmtDateTime(item.assessment_date))}</div>
          <div class="source-meta">${num(item.total_controls)} controls</div>
        </div>
        <span class="mono">${Number(item.compliance_score).toFixed(1)}%</span>
      </div>`
    )
    .join('');

  return `
    ${titleRow({
      title: 'Compliance',
      subtitle: report
        ? `NIST 800-53 Rev5 · ${num(report.total_controls)} controls · assessed ${relTime(report.assessment_date)}`
        : 'NIST 800-53 Rev5. Run an assessment to establish a baseline.',
      actions: `<button class="btn btn-primary" type="button" data-action="run-assessment">Run assessment</button>`,
    })}

    <div class="grid grid-main">
      <section class="panel">
        <div class="panel-head">
          <div><h2>Current posture</h2><p class="meta">Latest stored assessment</p></div>
          ${report ? `<span class="meta mono">${esc(report.assessment_id)}</span>` : ''}
        </div>
        <div class="panel-body">
          <div class="compliance-figure">
            <strong>${scored ? Number(summary.compliance_score).toFixed(1) : '—'}</strong>
            <span>${scored ? '% passing' : 'not assessed'}</span>
          </div>
          <div class="meter" aria-hidden="true"><span style="width:${scored ? Math.max(0, Math.min(100, summary.compliance_score)) : 0}%"></span></div>
          <div class="status-grid">${statusCells}</div>
          ${
            report && noData
              ? '<p class="notice" style="margin-top:16px">This report was scored without a cloud snapshot, so every control is <em>not assessed</em>. POST <code>aws_data</code> or <code>azure_data</code> with the assessment for a real score; <code>scripts/demo.py</code> shows the snapshot shape.</p>'
              : ''
          }
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Recent assessments</h2><span class="meta">${num(reports.total)}</span></div>
        ${historyRows || emptyState({ title: 'No assessments yet', text: 'Results are stored so you can compare runs.' })}
        <div class="panel-foot">Every run is stored with its score and timestamp, so posture can be compared after a restart.</div>
      </section>
    </div>

    <section class="panel section">
      <div class="panel-head">
        <div><h2>Controls</h2><p class="meta">${num(visible.length)} shown of ${num(controls.length)}</p></div>
        <div class="filter-row" style="margin:0" data-filters="compliance" data-auto>
          <label class="field inline"><span>Family</span>
            <select name="family">${selectOptions(families, filters.family, { all: 'All families' })}</select>
          </label>
          <label class="field inline"><span>Status</span>
            <select name="status">${selectOptions(['pass', 'fail', 'warning', 'not_assessed', 'not_applicable', 'error'], filters.status)}</select>
          </label>
        </div>
      </div>
      ${
        controlRows
          ? `<div class="table-wrap"><table class="table">
              <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Findings</th></tr></thead>
              <tbody>${controlRows}</tbody>
            </table></div>`
          : emptyState({
              title: report ? 'No controls match' : 'No assessment stored',
              text: report ? 'Try another family or status.' : 'Run an assessment to list the 25 automated NIST controls.',
            })
      }
    </section>`;
}

function unifiedNoData(dataSources) {
  if (!dataSources || typeof dataSources !== 'object') return false;
  return !dataSources.aws && !dataSources.azure;
}

/* ── ATT&CK ────────────────────────────────────────────────── */

async function renderAttack() {
  const [tacticsData, report] = await Promise.all([
    api(`${API}/mitre/tactics`),
    api(`${API}/mitre/report`),
  ]);

  const tactics = tacticsData.tactics || [];
  const mapped = tactics.reduce((sum, item) => sum + item.events_mapped, 0);
  const maxTactic = Math.max(1, ...tactics.map((item) => item.events_mapped));
  const allTechniques = report.top_techniques || [];
  const techniques = allTechniques.slice(0, 6);
  const chains = report.attack_chains || [];
  const missingTactics = tactics.filter((item) => item.events_mapped === 0).map((item) => item.name);
  const maxTechnique = Math.max(1, ...techniques.map((item) => item.count));

  const matrix = tactics
    .map(
      (tactic) => `<div class="tactic">
        <div class="tactic-name">${esc(tactic.name)}</div>
        <div class="tactic-count">${num(tactic.events_mapped)}</div>
        <div class="tactic-bar" aria-hidden="true"><span style="width:${(tactic.events_mapped / maxTactic) * 100}%"></span></div>
      </div>`
    )
    .join('');

  const techniqueRows = techniques
    .map(
      (technique) => `<div class="technique-row">
        <div>
          <div class="technique-name">${esc(technique.name)}</div>
          <div class="technique-id">${esc(technique.id)}</div>
        </div>
        <span class="technique-count">${num(technique.count)}</span>
        <div class="technique-track" aria-hidden="true"><span style="width:${(technique.count / maxTechnique) * 100}%"></span></div>
      </div>`
    )
    .join('');

  const chainRows = chains
    .map(
      (chain) => `<div class="chain">
        <div class="chain-head">
          <span class="chain-entity">${esc(chain.entity)}</span>
          ${severityChip(chain.risk_level)}
          <span class="muted small">${num(chain.stages)} stages · ${num(chain.total_events)} events</span>
        </div>
        <div class="chain-stages">${(chain.tactics || [])
          .map((tactic) => esc(tactic.name))
          .join(' → ')}</div>
      </div>`
    )
    .join('');

  return `
    ${titleRow({
      title: 'ATT&CK',
      subtitle: `${num(mapped)} mapped events across ${num(tactics.filter((t) => t.events_mapped > 0).length)} of 12 tactics. Coverage is computed from stored CloudTrail events.`,
      actions: refreshButton(),
    })}
    <section class="panel">
      <div class="panel-head">
        <div><h2>Kill-chain coverage</h2><p class="meta">Events per tactic · ${num(report.total_events_analyzed)} CloudTrail events analysed</p></div>
      </div>
      <div class="panel-body"><div class="tactic-grid">${matrix}</div></div>
    </section>

    <div class="grid grid-half section">
      <section class="panel">
        <div class="panel-head"><h2>Top techniques</h2><span class="meta">${techniques.length} of ${allTechniques.length} mapped</span></div>
        ${
          techniqueRows
            ? `<div class="technique-list">${techniqueRows}</div>`
            : emptyState({
                title: 'No techniques mapped',
                text: 'Collect CloudTrail events to populate the ATT&CK view.',
                action: collectButton('Collect events', 'ghost'),
              })
        }
      </section>

      <div class="stack">
        <section class="panel">
          <div class="panel-head"><h2>Attack chains</h2><span class="meta">${num(chains.length)} detected</span></div>
          ${
            chainRows ||
            emptyState({
              title: 'No multi-stage chains',
              text: 'A chain requires three or more tactics from the same source IP or user in the stored window.',
            })
          }
        </section>

        <section class="panel">
          <div class="panel-head"><h2>Detection rule</h2></div>
          <div class="panel-body">
            <dl class="detail-meta" style="margin-bottom:0">
              <div><dt>Minimum stages</dt><dd>3 distinct tactics</dd></div>
              <div><dt>Grouped by</dt><dd>source IP, then user</dd></div>
              <div><dt>Critical at</dt><dd>5 or more stages</dd></div>
              <div><dt>Window</dt><dd>stored CloudTrail events</dd></div>
            </dl>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head"><h2>Coverage gaps</h2><span class="meta">${missingTactics.length} tactics</span></div>
          <div class="panel-body">
            <p class="muted small">${
              missingTactics.length
                ? `${esc(missingTactics.join(', '))} have no mapped events in the stored window.`
                : 'Every tactic has at least one mapped event.'
            }</p>
          </div>
        </section>
      </div>
    </div>`;
}

/* ── Actions ───────────────────────────────────────────────── */

async function withBusy(button, busyLabel, task) {
  const previous = button ? button.innerHTML : '';
  if (button) {
    button.disabled = true;
    button.textContent = busyLabel;
  }
  try {
    return await task();
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = previous;
    }
  }
}

async function collectEvents(button) {
  await withBusy(button, 'Collecting…', async () => {
    const result = await api(`${API}/events/collect`, { method: 'POST' });
    const sources = result.results || {};
    const errors = Object.entries(sources).filter(([, value]) => value.status === 'error');
    const stored = result.stored || 0;

    if (errors.length) {
      toast(`Collection error: ${errors.map(([name]) => name).join(', ')}. See server logs.`, { error: true });
    } else if (stored === 0) {
      toast('Collection skipped. No cloud credentials are configured.');
    } else {
      toast(`Collection complete: ${num(stored)} event${stored === 1 ? '' : 's'} stored.`);
    }
    refreshShell();
    render({ focus: false });
  });
}

async function setAlertStatus(id, status, button) {
  await withBusy(button, status === 'resolved' ? 'Resolving…' : 'Saving…', async () => {
    await api(`${API}/alerts/${id}`, { method: 'PATCH', body: { status } });
    toast(`Alert #${id} ${status}.`);
    refreshShell();
    render({ focus: false });
  });
}

async function runAssessment(button) {
  await withBusy(button, 'Running…', async () => {
    const report = await api(`${API}/compliance/assess`, { method: 'POST', body: {} });
    toast(`Assessment complete: ${Number(report.compliance_score).toFixed(1)}% across ${num(report.total_controls)} controls.`);
    render({ focus: false });
  });
}

async function handleAction(button) {
  const action = button.dataset.action;
  switch (action) {
    case 'collect':
      return collectEvents(button);
    case 'refresh':
    case 'retry':
      return render({ focus: false });
    case 'open-key':
      return openKeyDialog();
    case 'ack-alert':
      return setAlertStatus(button.dataset.id, 'acknowledged', button);
    case 'resolve-alert':
      return setAlertStatus(button.dataset.id, 'resolved', button);
    case 'run-assessment':
      return runAssessment(button);
    case 'open-event':
      return openEventDrawer(Number(button.dataset.index));
    case 'copy-event':
      if (!state.lastEvent) return;
      try {
        await navigator.clipboard.writeText(JSON.stringify(state.lastEvent.details || {}, null, 2));
        toast('Event JSON copied.');
      } catch {
        toast('Clipboard is not available in this browser.', { error: true });
      }
      return;
    case 'load-more':
      state.eventsLimit += 50;
      return render({ focus: false });
    case 'clear-event-filters':
      state.filters.events = { severity: '', source: '' };
      state.eventsLimit = 50;
      return render({ focus: false });
    case 'recent-ioc': {
      const value = button.dataset.value;
      const type = button.dataset.type;
      try {
        await withBusy(button, 'Looking up…', () => lookupIoc(type, value));
        render({ focus: false });
      } catch (error) {
        toast(error.message, { error: true });
      }
      return;
    }
    default:
      return undefined;
  }
}

/* ── Routing ───────────────────────────────────────────────── */

function currentRoute() {
  const hash = location.hash.replace(/^#\/?/, '').trim();
  return SCREENS[hash] ? hash : 'overview';
}

async function render({ focus = false } = {}) {
  const route = currentRoute();
  const screen = SCREENS[route];
  const seq = ++renderSeq;

  document.querySelectorAll('.nav-item').forEach((item) => {
    const active = item.dataset.screen === route;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  document.title = `${screen.label} · Cloud SIEM`;
  if (isMobileNav()) setMobileNav(false);

  skeleton();
  try {
    const html = await screen.render();
    if (seq !== renderSeq) return;
    view.innerHTML = html;
    const status = document.getElementById('route-status');
    if (status) status.textContent = `${screen.label} loaded.`;
    if (focus) view.focus({ preventScroll: true });
  } catch (error) {
    if (seq !== renderSeq) return;
    view.innerHTML = `
      ${titleRow({ title: screen.label, subtitle: 'The view could not be loaded.' })}
      ${errorBlock(error)}
    `;
    if (!(error instanceof ApiError) || error.status !== 401) console.error(error);
  }
}

/* ── Event wiring ──────────────────────────────────────────── */

view.addEventListener('click', (event) => {
  const target = event.target.closest('[data-action]');
  if (!target || !view.contains(target)) return;
  if (target.dataset.action === 'open-event') {
    openEventDrawer(Number(target.dataset.index));
    return;
  }
  if (target.tagName !== 'BUTTON' && target.tagName !== 'A') return;
  event.preventDefault();
  handleAction(target).catch((error) => {
    toast(error.message || 'Action failed.', { error: true });
    if (error.status === 401) openKeyDialog('The API key was rejected.');
  });
});

view.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const row = event.target.closest('[data-action="open-event"]');
  if (!row) return;
  event.preventDefault();
  openEventDrawer(Number(row.dataset.index));
});

view.addEventListener('submit', (event) => {
  const filters = event.target.closest('form[data-filters]');
  if (filters) {
    event.preventDefault();
    readFilters(filters);
    render({ focus: false });
    return;
  }
  if (event.target.id === 'intel-form') {
    event.preventDefault();
    const data = new FormData(event.target);
    const type = String(data.get('type') || 'ip');
    const value = String(data.get('value') || '').trim();
    if (!value) return;
    const button = event.target.querySelector('button[type="submit"]');
    withBusy(button, 'Looking up…', () => lookupIoc(type, value))
      .then(() => render({ focus: false }))
      .catch((error) => toast(error.message, { error: true }));
  }
});

view.addEventListener('change', (event) => {
  const container = event.target.closest('[data-filters][data-auto]');
  if (!container) return;
  readFilters(container);
  render({ focus: false });
});

function readFilters(container) {
  const group = container.dataset.filters;
  const values = {};
  container.querySelectorAll('[name]').forEach((input) => {
    values[input.name] = input.value;
  });
  state.filters[group] = { ...state.filters[group], ...values };
  if (group === 'events') state.eventsLimit = 50;
}

/* ── Mobile navigation ────────────────────────────────────── */

menuBtn.addEventListener('click', () => {
  const open = !sidebar.classList.contains('open');
  setMobileNav(open);
});
backdrop.addEventListener('click', () => setMobileNav(false));
document.getElementById('nav-close').addEventListener('click', () => {
  setMobileNav(false);
  menuBtn.focus();
});
document.getElementById('mobile-refresh').addEventListener('click', () => render({ focus: false }));
sidebar.querySelectorAll('.nav-item').forEach((link) => {
  link.addEventListener('click', () => setMobileNav(false));
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && sidebar.classList.contains('open')) {
    setMobileNav(false);
    menuBtn.focus();
  }
});
window.addEventListener('resize', () => {
  if (!isMobileNav() && sidebar.classList.contains('open')) setMobileNav(false);
});

/* ── Start ─────────────────────────────────────────────────── */

window.addEventListener('hashchange', () => render({ focus: true }));
refreshShell();
render({ focus: true });
