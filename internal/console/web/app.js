// WordEye console.
//
// SECURITY NOTE, load-bearing: every value that originates from an agent —
// file paths, titles, evidence snippets, process command lines — is attacker
// influenced. It is malware content by definition. Nothing in this file ever
// assigns such a value through innerHTML; all text goes through textContent via
// the el() helper below.
//
// A stored-XSS here would let a compromised client site run script in the
// browser of the operator whose console can order containment across the whole
// estate. That is the worst outcome this system has, so the rule is absolute.

const api = {
  csrf: null,

  async call(method, path, body, retried = false) {
    const opts = {
      method,
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin',
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    // Always send the header on writes. Before sign-in there is no session to
    // bind it to, but its mere presence is what defeats cross-site login CSRF:
    // a browser will not set a custom header cross-origin without CORS.
    if (method !== 'GET') opts.headers['X-WordEye-CSRF'] = api.csrf || 'pre-session';

    const res = await fetch(path, opts);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
    if (!res.ok) {
      // A stale CSRF token is recoverable and must not surface as an error.
      //
      // The token is bound to the session, and a long-lived tab can be holding
      // one the server no longer accepts. The session itself is still valid, so
      // re-reading /api/me yields a token that works and the action proceeds.
      // Retried once only: a second failure is a real rejection, not staleness,
      // and looping would turn an authorisation problem into a request storm.
      if (res.status === 403 && !retried && /csrf/i.test((data && data.error) || '')) {
        const fresh = await api.call('GET', '/api/me', undefined, true);
        if (fresh && fresh.csrf) {
          api.csrf = fresh.csrf;
          if (typeof me === 'object' && me) me.csrf = fresh.csrf;
          return api.call(method, path, body, true);
        }
      }
      const err = new Error((data && data.error) || res.statusText || 'request failed');
      err.status = res.status;
      throw err;
    }
    return data;
  },
  get:  (p)    => api.call('GET', p),
  post: (p, b) => api.call('POST', p, b),
};

// --- DOM helpers -----------------------------------------------------------

// el(tag, attrs, ...children). Strings become text nodes, so untrusted content
// cannot become markup.
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) {
      // Only a real function becomes a listener. An on* key with a STRING
      // value would otherwise fall through to setAttribute and create an
      // inline handler — the one way to smuggle executable markup through a
      // helper whose whole purpose is to prevent that. The CSP forbids inline
      // script so it would not run today, but this helper must not depend on
      // a second control to be correct.
      if (typeof v === 'function') n.addEventListener(k.slice(2), v);
      continue;
    }
    else if (k === 'href' || k === 'src') {
      // Defence in depth. No agent-supplied value reaches href/src today, but
      // the entire XSS defence rests on this helper, so refuse URL schemes that
      // execute rather than navigate.
      const s = String(v).trim();
      if (/^(javascript|data|vbscript):/i.test(s)) continue;
      n.setAttribute(k, s);
    }
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

const $  = (sel) => document.querySelector(sel);
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

// render replaces the view with the given nodes, dropping absent ones.
//
// Node.append() STRINGIFIES null and undefined into visible "null" text rather
// than ignoring them, so the common `cond ? panel : null` idiom silently prints
// the word null into the page. el() already guards its children; this gives the
// top-level calls the same guarantee, in one place, instead of relying on every
// call site to remember.
function render(...nodes) {
  const view = clear($('#view'));
  for (const n of nodes.flat()) {
    if (n === null || n === undefined || n === false) continue;
    view.append(n);
  }
  return view;
}

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  setTimeout(() => t.classList.add('hidden'), 6000);
}

function ago(ts) {
  if (!ts) return 'never';
  const then = typeof ts === 'number' ? ts * 1000 : Date.parse(ts);
  if (!then || then < 0) return 'never';
  const s = Math.floor((Date.now() - then) / 1000);
  if (s < 0) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

// What the four finding states mean, expressed as what happens on the NEXT
// sighting — which is the only real difference between them.
//
// The distinction that matters in practice is contained vs resolved. "Resolved"
// claims the artefact is gone, so if an agent sees it again that is a
// reinfection and the finding reopens. "Contained" claims it has been dealt
// with, and the artefact still being present is expected, so it stays closed
// and stops counting against the estate. Reopening contained findings meant
// every triage decision was undone by the next report and the open counts never
// moved.
const STATE_HELP = {
  open: 'Untriaged. Counts towards the open findings for this estate.',
  contained: 'Dealt with. Stays closed even though the agent still sees it, and stops counting. '
    + 'Use when the threat is neutralised but the file or artefact is still on disk.',
  resolved: 'Gone. If an agent sees it again this reopens automatically, because a fixed thing '
    + 'coming back is a reinfection.',
  dismissed: 'Not a real finding. Stays closed permanently and is excluded from cross-estate '
    + 'correlation, so it will not corroborate anything.',
};

const sevBadge = (s) => el('span', { class: 'badge sev-' + (s || 'info'), text: s || 'info' });

function statusCell(status) {
  return el('span', { class: 'st-' + status },
    el('span', { class: 'dot', text: '●' }), status);
}

// --- auth flow -------------------------------------------------------------

let me = null;

async function boot() {
  try {
    me = await api.get('/api/me');
    api.csrf = me.csrf;
  } catch {
    return showLogin();
  }
  if (!me.totp_enrolled) return showMfaSetup();
  if (!me.mfa_ok) return showMfaVerify();
  return showApp();
}

function showStep(id) {
  $('#app').classList.add('hidden');
  $('#auth').classList.remove('hidden');
  for (const s of document.querySelectorAll('#auth .step')) s.classList.add('hidden');
  if (id) $(id).classList.remove('hidden');
}

const showLogin     = () => showStep('#login-form');
const showMfaVerify = () => { showStep('#mfa-form'); $('#mfa-code').focus(); };

async function showMfaSetup() {
  // Stop the background refresh before rendering the QR.
  //
  // The fifteen-second poll re-entered this function, which re-requested the
  // enrolment secret; combined with a server that minted a new secret on every
  // request, the code behind the QR changed while the user was still typing the
  // six digits from it. The server now resumes an enrolment in progress, so
  // this is no longer load-bearing — but a screen showing a QR code has no
  // business polling fleet statistics anyway.
  clearInterval(refreshTimer);
  showStep('#mfa-setup');
  try {
    const d = await api.post('/api/mfa/setup', {});
    $('#qr').src = d.qr;
    $('#secret').textContent = d.secret;
  } catch (e) {
    $('#confirm-err').textContent = e.message;
  }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-err').textContent = '';
  try {
    const d = await api.post('/api/login', {
      username: $('#login-user').value,
      password: $('#login-pass').value,
    });
    api.csrf = d.csrf;
    $('#login-pass').value = '';
    if (!d.totp_enrolled) return showMfaSetup();
    return showMfaVerify();
  } catch (err) {
    $('#login-err').textContent = err.message;
  }
});

$('#mfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#mfa-err').textContent = '';
  try {
    await api.post('/api/mfa/verify', { code: $('#mfa-code').value.trim() });
    $('#mfa-code').value = '';
    me = await api.get('/api/me');
    api.csrf = me.csrf;
    showApp();
  } catch (err) {
    $('#mfa-err').textContent = err.message;
  }
});

$('#confirm-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#confirm-err').textContent = '';
  try {
    const d = await api.post('/api/mfa/confirm', { code: $('#confirm-code').value.trim() });
    showStep('#recovery');
    $('#recovery-codes').textContent = (d.recovery_codes || []).join('\n');
  } catch (err) {
    $('#confirm-err').textContent = err.message;
  }
});

$('#recovery-done').addEventListener('click', async () => {
  me = await api.get('/api/me');
  api.csrf = me.csrf;
  showApp();
});

$('#logout').addEventListener('click', async () => {
  try { await api.post('/api/logout', {}); } catch { /* signing out regardless */ }
  location.hash = '';
  location.reload();
});

// --- shell -----------------------------------------------------------------

let refreshTimer = null;

function showApp() {
  $('#auth').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#whoami').textContent = me.username + ' (' + me.role + ')';
  for (const n of document.querySelectorAll('.admin-only')) {
    n.classList.toggle('hidden', !me.can_admin);
  }
  if (me.totp_enrolled && me.recovery_codes === 0) {
    toast('No recovery codes remain. If you lose your authenticator you will need an admin to reset MFA.', 'bad');
  }
  window.addEventListener('hashchange', route);
  route();

  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { refreshStats(); if (currentView === 'fleet') route(); }, 15000);
}

let currentView = '';

async function refreshStats() {
  let s;
  try { s = await api.get('/api/stats'); } catch { return; }
  const tiles = [
    ['agents',  s.agents,        ''],
    ['online',  s.online,        s.online === s.agents ? 'good' : ''],
    ['stale',   s.stale,         s.stale ? 'high' : ''],
    ['offline', s.offline,       s.offline ? 'crit' : ''],
    ['critical findings', s.open_critical, s.open_critical ? 'crit' : 'good'],
    ['high findings',     s.open_high,     s.open_high ? 'high' : ''],
    ['awaiting approval', s.pending_commands, s.pending_commands ? 'high' : ''],
    ['correlated',        s.correlated_artifacts, s.correlated_artifacts ? 'crit' : ''],
  ];
  clear($('#stats')).append(...tiles.map(([k, n, cls]) =>
    el('div', { class: 'tile ' + cls }, el('div', { class: 'n', text: String(n ?? 0) }), el('div', { class: 'k', text: k }))));
}

// can(action) asks the server-supplied permission map rather than testing role
// names in the UI. Hiding a control is a courtesy, never a security boundary —
// every route re-checks server-side — but it keeps the UI honest about what a
// role can do, and means per-estate RBAC needs no change here.
function can(action) {
  return !!(me && me.permissions && me.permissions[action]);
}

// download() POSTs and saves the response as a file.
//
// The generic api.call() reads the body as text, which would corrupt an
// executable. Installers are binaries, so this path keeps the response as a
// blob and never stringifies it.
async function download(path, body, fallbackName) {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-WordEye-CSRF': api.csrf || '' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = JSON.parse(await res.text()); if (j && j.error) msg = j.error; } catch { /* binary or empty */ }
    const err = new Error(msg); err.status = res.status; throw err;
  }
  // Prefer the filename the server chose; it encodes the estate and platform.
  let name = fallbackName;
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="?([^"]+)"?/.exec(cd);
  if (m) name = m[1];

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  // Revoke on the next tick; revoking synchronously can cancel the download.
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  return name;
}

const views = {
  estates: viewEstates,
  fleet: viewFleet,
  findings: viewFindings,
  correlations: viewCorrelations,
  schedules: viewSchedules,
  commands: viewCommands,
  tokens: viewTokens,
  users: viewUsers,
  audit: viewAudit,
  agent: viewAgent,
};

function route() {
  const hash = (location.hash || '#/fleet').slice(2);
  const [name, arg] = hash.split('/');
  currentView = views[name] ? name : 'fleet';
  for (const a of document.querySelectorAll('header nav a')) {
    a.classList.toggle('active', a.dataset.view === currentView);
  }
  refreshStats();
  views[currentView](arg).catch((e) => {
    if (e.status === 401 || e.status === 403) return boot();
    render(el('div', { class: 'empty', text: e.message }));
  });
}

function panel(title, ...body) {
  return el('section', { class: 'panel' }, el('h2', { text: title }), ...body);
}

function table(headers, rows) {
  if (!rows.length) return el('div', { class: 'empty', text: 'Nothing to show.' });
  return el('table', {},
    el('thead', {}, el('tr', {}, ...headers.map((h) => el('th', { text: h })))),
    el('tbody', {}, ...rows));
}

// --- fleet -----------------------------------------------------------------

// estateName resolves an id to a name for the scoping banner. Cached because
// the fleet view re-renders on a timer and the estate list rarely changes.
let estateCache = null;
async function estateName(id) {
  if (!id) return '';
  if (!estateCache) {
    try { estateCache = await api.get('/api/estates'); } catch { estateCache = []; }
  }
  const e = estateCache.find((x) => String(x.id) === String(id));
  return e ? e.name : ('estate ' + id);
}

// A banner making the current scope unmistakable. A filtered view that looks
// like the whole fleet is how an operator concludes an estate is quiet when
// they are simply not looking at it.
function scopeBanner(name, clearHash) {
  return el('div', { class: 'form' },
    el('span', { class: 'badge', text: name }),
    el('span', { class: 'dim tiny', text: ' — showing this customer only. ' }),
    el('a', { href: clearHash, class: 'dim', text: 'Show all' }));
}

async function viewFleet(estateID) {
  const agents = await api.get('/api/agents' + (estateID ? '?estate=' + encodeURIComponent(estateID) : ''));

  // Multi-select. Triage on a large estate is a fleet operation: asking for a
  // sweep of forty hosts should be one action, not forty.
  const selected = new Set();
  const selCount = el('span', { class: 'dim tiny', text: 'none selected' });
  const refreshSel = () => {
    selCount.textContent = selected.size ? selected.size + ' selected' : 'none selected';
  };
  const boxFor = (a) => {
    const cb = el('input', { type: 'checkbox' });
    cb.addEventListener('click', (ev) => ev.stopPropagation());
    cb.addEventListener('change', () => {
      if (cb.checked) selected.add(a.id); else selected.delete(a.id);
      refreshSel();
    });
    return cb;
  };

  const rows = agents.map((a) => el('tr', { class: 'clickable', onclick: () => { location.hash = '#/agent/' + a.id; } },
    el('td', {}, boxFor(a)),
    // Hostname identifies the machine; the installer label identifies the
    // batch it was enrolled from. Triage needs the former.
    el('td', {},
      el('div', { class: 'mono', text: a.hostname || a.label || a.id }),
      el('div', { class: 'dim tiny', text: [a.site || a.webroot || '', a.label || ''].filter(Boolean).join('  ·  ') })),
    el('td', {}, statusCell(a.status)),
    el('td', { class: 'dim', text: ago(a.last_seen) }),
    el('td', {}, a.monitor_active ? el('span', { class: 'st-online', text: 'monitoring' }) : el('span', { class: 'dim', text: 'idle' })),
    el('td', { class: 'num' }, a.open_critical ? el('span', { class: 'badge sev-critical', text: String(a.open_critical) }) : '—'),
    el('td', { class: 'num' }, a.open_high ? el('span', { class: 'badge sev-high', text: String(a.open_high) }) : '—'),
    el('td', {}, a.allow_remote_contain && a.agent_opts_in_contain
      ? el('span', { class: 'st-online', text: 'permitted' })
      : el('span', { class: 'dim', text: 'blocked' })),
    el('td', { class: 'dim mono tiny', text: a.version || '' })));

  const title = estateID ? 'Fleet — ' + (await estateName(estateID)) : 'Fleet';
  async function runBulk(kind) {
    if (!selected.size) { toast('Select one or more hosts first.', 'bad'); return; }
    if (!confirm('Run ' + kind + ' on ' + selected.size + ' host(s)?')) return;
    try {
      const r = await api.post('/api/commands/bulk', { agents: [...selected], kind });
      toast('Queued ' + r.queued + ' ' + kind + ' command(s)' + (r.failed ? ', ' + r.failed + ' failed' : '') + '.', 'good');
    } catch (e) { toast(e.message, 'bad'); }
  }

  const selectAll = el('button', { class: 'ghost', onclick: () => {
    const boxes = document.querySelectorAll('#view tbody input[type=checkbox]');
    const turnOn = selected.size !== agents.length;
    boxes.forEach((b, i) => {
      b.checked = turnOn;
      if (turnOn) selected.add(agents[i].id); else selected.delete(agents[i].id);
    });
    refreshSel();
  } }, 'Select all');

  // Only non-destructive work is offered across a selection. Containment stays
  // per-host behind its own approval: "run this on everything" is exactly the
  // wrong shape for an action that deletes things.
  const bulkBar = el('div', { class: 'filters', style: 'align-items:center' },
    selectAll, selCount,
    el('button', { class: 'ghost', onclick: () => runBulk('scan') }, 'Run scan'),
    el('button', { class: 'ghost', onclick: () => runBulk('baseline') }, 'Re-baseline'),
    el('button', { class: 'ghost', onclick: () => runBulk('verify') }, 'Verify'),
    el('a', { href: '#/schedules', class: 'dim tiny', text: 'Schedules →' }));

  render(
    estateID ? scopeBanner(await estateName(estateID), '#/fleet') : null,
    panel(title,
      bulkBar,
      table(['', 'Host', 'Status', 'Last seen', 'Mode', 'Crit', 'High', 'Remote containment', 'Version'], rows)),
    estateID
      ? el('div', { class: 'form' },
          el('a', { href: '#/findings/' + encodeURIComponent(estateID), class: 'dim',
                    text: 'View this customer’s findings →' }))
      : null);
}

// --- agent detail ----------------------------------------------------------

async function viewAgent(id) {
  const d = await api.get('/api/agents/' + encodeURIComponent(id));
  const a = d.agent;
  const containable = a.allow_remote_contain && a.agent_opts_in_contain;

  const info = el('dl', { class: 'kv' },
    el('dt', { text: 'Agent' }),    el('dd', { text: a.id }),
    el('dt', { text: 'Hostname' }), el('dd', { text: a.hostname || '—' }),
    el('dt', { text: 'Site' }),     el('dd', { text: a.site || '—' }),
    el('dt', { text: 'Webroot' }),  el('dd', { text: a.webroot || '—' }),
    el('dt', { text: 'Version' }),  el('dd', { text: a.version || '—' }),
    el('dt', { text: 'Platform' }), el('dd', { text: (a.os || '?') + '/' + (a.arch || '?') }),
    el('dt', { text: 'Last seen' }),el('dd', { text: ago(a.last_seen) + ' from ' + (a.last_ip || '?') }),
    el('dt', { text: 'Enrolled' }), el('dd', { text: new Date(a.enrolled_at).toLocaleString() }));

  const actions = el('div', { class: 'form' },
    el('button', { class: 'ghost', onclick: () => queue(a.id, 'scan') }, 'Run scan'),
    el('button', { class: 'ghost', onclick: () => queue(a.id, 'baseline') }, 'Take baseline'),
    el('button', { class: 'ghost', onclick: () => queue(a.id, 'verify') }, 'Verify drift'),
    el('button', { class: 'ghost', onclick: () => queue(a.id, 'contain_dryrun') }, 'Containment dry run'),
    containable
      ? el('button', { class: 'danger', onclick: () => queueContain(a.id) }, 'Order containment')
      : el('span', { class: 'dim tiny' },
          'Remote containment blocked: ',
          !a.allow_remote_contain ? 'the enrollment token did not grant it' : 'this host did not opt in'));

  // Retiring removes a host from the fleet view without deleting its history.
  // Decommissioned servers and test agents otherwise sit in the list forever,
  // and a fleet that is mostly noise is a fleet nobody reads.
  const retire = can('fleet.retire') ? el('div', { class: 'form' },
    el('button', {
      class: 'ghost',
      onclick: async () => {
        // Confirm by name: retiring the wrong host hides a live agent, and a
        // hidden agent is one nobody notices has stopped reporting.
        if (!confirm('Retire ' + (a.hostname || a.label || a.id) + '?\n\n' +
            'It disappears from the fleet but its findings and history are kept. ' +
            'If the agent is still running it will reappear on its next check-in.')) {
          return;
        }
        try {
          await api.post('/api/agents/' + encodeURIComponent(a.id) + '/retire', {});
          toast('Retired.', 'good');
          location.hash = '#/fleet';
        } catch (e) { toast(e.message, 'bad'); }
      },
    }, 'Retire agent'),
    el('span', { class: 'dim tiny' },
      'Hides it from the fleet. Findings and audit history are preserved.')) : null;

  const findings = d.findings || [];
  const fRows = findings.map((f) => findingRow(f, false));

  const cmdRows = (d.commands || []).map(commandRow);

  // Uninstalling through the console is the blessed way to remove an agent.
  //
  // It matters because of the watchdog: once an unexplained disappearance is a
  // security finding, an administrator who simply kills the process and deletes
  // the files produces the exact signature of an intruder. This path records the
  // removal, so everything else stays suspicious for a reason.
  const uninstall = el('div', { class: 'form' },
    el('button', { class: 'danger', onclick: async () => {
      if (!confirm('Uninstall the agent on ' + (a.hostname || a.id) + '?' + String.fromCharCode(10) + String.fromCharCode(10)
        + 'It will delete its credential and stop. This needs a second approver before it is sent, '
        + 'and the host stops being monitored once it runs.')) return;
      try {
        await api.post('/api/commands', { agent: a.id, kind: 'uninstall' });
        toast('Uninstall queued; it needs approval before dispatch.', 'good');
        route();
      } catch (e) { toast(e.message, 'bad'); }
    } }, 'Uninstall agent'),
    el('span', { class: 'dim tiny', text: 'Removes the credential and stops the agent. Requires approval. '
      + 'Use this rather than killing the process, so the disappearance is not reported as tampering.' }));

  render(
    el('div', { class: 'form' }, el('a', { href: '#/fleet', class: 'dim', text: '← back to fleet' })),
    panel(a.hostname || a.label || a.id, info, actions, retire, uninstall),
    panel('Findings (' + findings.length + ')',
      table(['Severity', 'Rule', 'Path / target', 'State', 'Seen', ''], fRows)),
    panel('Recent commands', table(['Created', 'Kind', 'Status', 'By', 'Detail'], cmdRows)));
}

async function queue(agentId, kind) {
  try {
    const c = await api.post('/api/commands', { agent_id: agentId, kind, params: {} });
    toast(c.requires_approval
      ? 'Queued and awaiting approval.'
      : 'Queued. It will run at the agent’s next check-in.', 'good');
    route();
  } catch (e) { toast(e.message, 'bad'); }
}

async function queueContain(agentId) {
  const ok = confirm(
    'Order containment on this host?\n\n' +
    'The agent will disable persistence, freeze and capture implant processes, kill them, ' +
    'quarantine confirmed malicious files, and flush OPcache.\n\n' +
    'It health-checks the site after every destructive step and rolls back automatically if it stops serving.\n\n' +
    'This still requires a separate approval before it is dispatched.');
  if (!ok) return;
  await queue(agentId, 'contain');
}

// --- findings --------------------------------------------------------------

function findingRow(f, showAgent) {
  const target = f.path || (f.contain_pid ? 'pid ' + f.contain_pid : '');
  const row = el('tr', {},
    el('td', {}, sevBadge(f.severity), el('div', { class: 'dim tiny', text: f.confidence || '' })),
    // Hostname first, label beneath.
    //
    // The label comes from the installer, so every host enrolled from the same
    // one carries the same string: an eighteen-host estate showed eighteen rows
    // reading "installer: fleet-rollout (linux-amd64)", which says nothing about which
    // machine to open a shell on. The hostname is the answer to that question,
    // and it is what triage actually needs.
    showAgent
      ? el('td', {},
          el('div', { class: 'mono', text: f.agent_hostname || f.agent_id }),
          f.agent_label && f.agent_label !== f.agent_hostname
            ? el('div', { class: 'dim tiny', text: f.agent_label })
            : null)
      : null,
    el('td', {}, el('div', { text: f.title || f.rule_id }), el('div', { class: 'dim tiny mono', text: f.rule_id })),
    el('td', { class: 'mono tiny', text: target }),
    el('td', {}, el('span', { class: 'dim', text: f.state })),
    el('td', { class: 'dim tiny', text: ago(f.last_seen) }),
    el('td', {}, el('button', { class: 'ghost', onclick: (e) => toggleDetail(e, f, showAgent) }, 'Details')));
  return row;
}

function toggleDetail(ev, f, showAgent) {
  const tr = ev.target.closest('tr');
  if (tr.nextSibling && tr.nextSibling.classList && tr.nextSibling.classList.contains('detail-row')) {
    tr.nextSibling.remove();
    return;
  }
  const span = showAgent ? 7 : 6;
  const body = el('td', { colspan: String(span) },
    f.detail ? el('p', { text: f.detail }) : null,
    f.remediation ? el('p', {}, el('strong', { text: 'Remediation: ' }), f.remediation) : null,
    f.sha256 ? el('p', { class: 'mono tiny' }, 'sha256 ' + f.sha256) : null,
    f.evidence ? el('pre', { class: 'evidence', text: f.evidence }) : null,
    el('div', { class: 'actions' },
      ...['contained', 'dismissed', 'resolved', 'open']
        .filter((s) => s !== f.state)
        .map((s) => el('button', {
          class: 'ghost',
          // The four states differ in what happens when the agent sees this
          // artefact AGAIN, which is the only thing that distinguishes them and
          // is not guessable from the labels.
          title: STATE_HELP[s] || '',
          onclick: async () => {
            try {
              await api.post('/api/findings/' + f.id + '/state', { state: s, note: '' });
              toast('Marked ' + s, 'good');
              route();
            } catch (e) { toast(e.message, 'bad'); }
          },
        }, 'Mark ' + s))),
    el('p', { class: 'dim tiny', text: STATE_HELP[f.state] || '' }));
  tr.after(el('tr', { class: 'detail-row' }, body));
}

async function viewFindings(estateID) {
  const params = new URLSearchParams(location.search);
  const state = el('select', {},
    ...['open', '', 'contained', 'dismissed', 'resolved'].map((s) =>
      el('option', { value: s, text: s || 'any state' })));
  const sev = el('select', {},
    ...['', 'critical', 'high', 'medium', 'low', 'info'].map((s) =>
      el('option', { value: s, text: s || 'any severity' })));
  const q = el('input', {
    placeholder: 'host:web-01   ·   severity:critical AND path:uploads   ·   meta.score:>20',
    value: params.get('q') || '',
    style: 'min-width:34rem',
  });
  // A parse error must be visible. A search box that silently returns
  // everything when the query is wrong teaches an operator to trust a result
  // that does not mean what they think it means.
  const qErr = el('div', { class: 'dim tiny' });

  // Ready-made queries. On a 236-host estate the hard part is knowing where to
  // start, and these are the questions an analyst actually opens with.
  const presets = [
    ['Unreviewed criticals', 'severity:critical AND state:open'],
    ['Strong heuristic hits', 'meta.score:>20'],
    ['Anything in uploads', 'path:uploads'],
    ['YARA matches', 'rule:yara.*'],
    ['Hide bulk timestomps', 'state:open AND NOT rule:timestomp'],
    ['Differs from published release', 'rule:prov.modified'],
  ];
  const presetBar = el('div', { class: 'form' },
    el('span', { class: 'dim tiny', text: 'Start from: ' }),
    ...presets.map(([label, query]) =>
      el('button', {
        class: 'ghost',
        onclick: () => { q.value = query; load().catch(() => {}); },
      }, label)));

  const body = el('div', {});
  const PAGE = 200;
  let offset = 0;

  async function load() {
    const qs = new URLSearchParams();
    if (sev.value) qs.set('severity', sev.value);
    if (state.value) qs.set('state', state.value);
    if (q.value.trim()) qs.set('q', q.value.trim());
    if (estateID) qs.set('estate', estateID);
    qs.set('limit', String(PAGE));
    qs.set('offset', String(offset));
    let res;
    try {
      res = await api.get('/api/findings?' + qs.toString());
      qErr.textContent = '';
    } catch (e) {
      // Say what is wrong and show nothing, rather than showing everything.
      qErr.textContent = e.message;
      clear(body);
      return;
    }
    const list = res.findings || [];
    const total = res.total || 0;
    const from = total === 0 ? 0 : offset + 1;
    const to = offset + list.length;

    const prev = el('button', { class: 'ghost', onclick: () => { offset = Math.max(0, offset - PAGE); load().catch(() => {}); } }, 'Previous');
    const next = el('button', { class: 'ghost', onclick: () => { offset += PAGE; load().catch(() => {}); } }, 'Next');
    if (offset === 0) prev.disabled = true;
    if (to >= total) next.disabled = true;

    // State the range AND the total. A truncated list that presents itself as
    // the whole set is how an operator concludes an estate is clean.
    // Bulk triage. A rule that was too noisy leaves its output behind
    // permanently — findings never age out — so fixing the rule cannot retract
    // what it already wrote. At 4,866 rows, clearing them individually is not a
    // real option, and without this the fix does not change any number an
    // operator looks at.
    const bulk = el('button', {
      class: 'ghost',
      title: 'Apply a state to every finding matching the current filter, not just this page.',
      onclick: () => bulkState(total),
    }, 'Bulk triage all ' + total);

    const pager = el('div', { class: 'filters', style: 'justify-content:space-between;align-items:center' },
      el('div', { class: 'dim tiny',
        text: total === 0
          ? 'No findings match this filter.'
          : 'Showing ' + from + String.fromCharCode(8211) + to + ' of ' + total + (estateID ? ' for this customer' : '') }),
      el('div', { class: 'actions' }, total > 0 ? bulk : null, prev, next));

    clear(body).append(
      pager,
      table(
        ['Severity', 'Agent', 'Finding', 'Path / target', 'State', 'Seen', ''],
        list.map((f) => findingRow(f, true))),
      total > PAGE ? pager.cloneNode(true) : null);

    // cloneNode drops listeners, so the bottom pager gets its own buttons.
    if (total > PAGE) {
      const bottom = body.lastChild;
      const btns = bottom.querySelectorAll('button');
      if (btns[0]) btns[0].addEventListener('click', () => { offset = Math.max(0, offset - PAGE); load().catch(() => {}); });
      if (btns[1]) btns[1].addEventListener('click', () => { offset += PAGE; load().catch(() => {}); });
    }
  }

  // bulkState re-states everything the CURRENT filter matches.
  //
  // It sends the same filter the list used and the count the operator was
  // shown; the server refuses if reality has moved, so a report arriving
  // mid-click cannot widen what gets changed.
  async function bulkState(total) {
    const NL = String.fromCharCode(10);
    const menu = [
      'Apply which state to all ' + total + ' matching findings?',
      '',
      'dismissed  - not real findings, excluded from correlation',
      'contained  - dealt with, stops counting, will not reopen',
      'resolved   - gone; reopens automatically if seen again',
      'open       - back to untriaged',
    ].join(NL);
    const target = prompt(menu, 'dismissed');
    if (!target) return;
    const note = prompt('Note (recorded in the audit log):', '') || '';
    if (!confirm('Mark ' + total + ' finding(s) as ' + target + '?' + NL + NL
        + 'This cannot be undone in bulk.')) return;

    const payload = {
      state: target.trim(), note,
      severity: sev.value || '', from_state: state.value || '',
      q: q.value.trim(), estate: estateID ? Number(estateID) : 0,
      expect: total,
    };
    try {
      const r = await api.post('/api/findings/bulk-state', payload);
      toast('Updated ' + r.changed + ' finding(s).', 'good');
      offset = 0;
      await load();
      refreshStats();
    } catch (e) { toast(e.message, 'bad'); }
  }

  // Any change of filter returns to the first page: staying on page 12 of a
  // result set that no longer has twelve pages shows an empty table and reads
  // as "nothing found".
  function reload() { offset = 0; load().catch(() => {}); }
  for (const c of [sev, state]) c.addEventListener('change', reload);
  let t;
  q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(reload, 250); });

  render(
    estateID ? scopeBanner(await estateName(estateID), '#/findings') : null,
    el('section', { class: 'panel' },
      el('h2', { text: 'Findings' }),
      el('div', { class: 'filters' }, q, sev, state),
      qErr,
      presetBar,
      el('details', { class: 'dim tiny', style: 'padding:0 1rem 0.5rem' },
        el('summary', { text: 'Query syntax' }),
        el('pre', { class: 'evidence', text:
          'field:value        substring match      path:uploads\n' +
          'field:*glob*       wildcard             rule:yara.*\n' +
          'field:>N  field:<N numeric comparison   meta.score:>20\n' +
          'AND  OR  NOT  ( )  boolean              (severity:critical OR severity:high) AND NOT rule:timestomp\n' +
          'bare word          free text            uploads\n\n' +
          'Fields: severity, rule, class, confidence, state, path, sha256, title,\n' +
          '        detail, evidence, agent, host, site, estate, line, size, seen,\n' +
          '        and meta.<key> for a finding’s own metadata.' })),
      body));
  await load();
}

// --- correlations ----------------------------------------------------------

// Ordered by how urgently a human should look. A campaign is an active
// incident; vendor code is the answer "this is fine" and belongs at the bottom.
const VERDICT_RANK = { campaign: 0, singleton: 1, inconclusive: 2, vendor: 3 };
const VERDICT_TEXT = {
  campaign: 'campaign',
  singleton: 'singleton',
  vendor: 'vendor code',
  inconclusive: 'inconclusive',
};
const verdictBadge = (v) =>
  el('span', { class: 'badge vd-' + (VERDICT_TEXT[v] ? v : 'inconclusive'),
               text: VERDICT_TEXT[v] || 'inconclusive' });

// How long the artefact took to spread. Nine hosts in four minutes is a
// deployment or an attack; nine hosts over two years is a plugin. The same row
// without this distinction is unactionable.
function spreadOf(c) {
  if (!c.first_seen || !c.last_seen || c.count < 2) return '';
  const s = c.last_seen - c.first_seen;
  if (s < 300) return 'appeared across all hosts within ' + Math.max(s, 1) + 's';
  if (s < 86400) return 'spread over ' + Math.round(s / 3600) + 'h';
  return 'spread over ' + Math.round(s / 86400) + 'd';
}

// Hand the digest to the findings query view rather than making an analyst
// retype it. pushState keeps the SPA alive; a full navigation would discard it.
function openQuery(q) {
  history.pushState(null, '', '?q=' + encodeURIComponent(q) + '#/findings');
  route();
}

function correlationRows(c) {
  const hosts = c.agents || [];
  const paths = c.paths || [];
  const more = (xs, n) => (xs.length > n ? ' +' + (xs.length - n) + ' more' : '');

  return [
    el('tr', {},
      el('td', {}, verdictBadge(c.verdict), el('div', { style: 'margin-top:.25rem' }, sevBadge(c.severity))),
      el('td', {},
        el('div', { text: c.title || '(untitled)' }),
        el('div', { class: 'dim tiny mono', text: c.rule_id || '' }),
        el('div', { class: 'dim tiny mono', text: (c.sha256 || '').slice(0, 32) })),
      el('td', { class: 'num' },
        el('div', { text: String(c.count) }),
        c.sites_running_tree
          ? el('div', { class: 'dim tiny', text: 'of ' + c.sites_running_tree + ' with this plugin' })
          : null),
      el('td', { class: 'tiny' },
        el('div', { text: 'first ' + ago(c.first_seen) }),
        el('div', { class: 'dim', text: 'last ' + ago(c.last_seen) }),
        el('div', { class: 'dim', text: spreadOf(c) })),
      el('td', { class: 'tiny', title: hosts.join('\n') },
        el('div', { text: hosts.slice(0, 3).join(', ') + more(hosts, 3) })),
      el('td', { class: 'tiny mono', title: paths.join('\n') },
        ...paths.slice(0, 2).map((x) => el('div', { text: x })),
        paths.length > 2 ? el('div', { class: 'dim', text: more(paths, 2).trim() }) : null),
      el('td', {},
        el('button', { class: 'ghost', onclick: () => openQuery('sha256:' + c.sha256) }, 'Investigate'))),
    // The verdict's reasoning, in full, on its own line. An operator has to be
    // able to disagree with the conclusion, which means seeing the argument.
    el('tr', { class: 'sub' },
      el('td', { colspan: '7', class: 'dim tiny', text: c.rationale || '' })),
  ];
}

async function viewCorrelations(estateID) {
  const cors = await api.get('/api/correlations' + (estateID ? '?estate=' + encodeURIComponent(estateID) : ''));
  cors.sort((a, b) =>
    ((VERDICT_RANK[a.verdict] ?? 2) - (VERDICT_RANK[b.verdict] ?? 2)) || (b.count - a.count));

  const rows = cors.flatMap(correlationRows);
  const body = rows.length
    ? table(['Verdict', 'Artefact', 'Hosts', 'Timeline', 'Seen on', 'Paths', ''], rows)
    // An empty page must say why it is empty. "Nothing to show" reads as
    // "nothing is wrong", when the truth is usually "not enough hosts yet".
    : el('div', { class: 'empty' },
        el('div', { text: 'No artefact has been seen on two or more hosts.' }),
        el('div', { class: 'dim tiny', style: 'margin-top:.4rem',
          text: 'Correlation needs at least two distinct installations reporting identical bytes. '
              + 'Multiple enrollments of the same host and webroot count once, and retired agents do not count at all.' }));

  render(
    estateID ? scopeBanner(await estateName(estateID), '#/correlations') : null,
    panel('Identical artefacts across hosts',
      el('p', { class: 'dim', style: 'padding:0 1rem' },
        'The same SHA-256 on several installations is one event, not several coincidences. '
        + 'A campaign is one incident to work as a unit — look for a shared credential, deployment pipeline or '
        + 'backdoored plugin. Vendor code is corroborated by the estate and can be exonerated. A singleton is a '
        + 'file present on one site but absent from the others running the same plugin, which is what a targeted '
        + 'implant looks like.'),
      body));
}


// --- scheduled scans -------------------------------------------------------

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function weekdaysText(mask) {
  if ((mask & 127) === 127) return 'every day';
  if ((mask & 62) === 62 && !(mask & 65)) return 'weekdays';
  const out = [];
  for (let i = 0; i < 7; i++) if (mask & (1 << i)) out.push(DAYS[i]);
  return out.join(', ') || 'never';
}

function hhmm(minuteOfDay) {
  const h = String(Math.floor(minuteOfDay / 60)).padStart(2, '0');
  const m = String(minuteOfDay % 60).padStart(2, '0');
  return h + ':' + m;
}

async function viewSchedules() {
  const [list, estates] = await Promise.all([
    api.get('/api/schedules'),
    api.get('/api/estates').catch(() => []),
  ]);

  const name = el('input', { placeholder: 'Nightly deep scan', style: 'min-width:16rem' });
  const kind = el('select', {}, ...['scan', 'baseline', 'verify'].map((k) => el('option', { value: k, text: k })));
  const time = el('input', { type: 'time', value: '03:00' });
  const tz = el('input', { value: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', style: 'min-width:12rem' });
  const jitter = el('input', { type: 'number', value: '30', min: '0', max: '240', style: 'width:5rem' });
  const estate = el('select', {},
    el('option', { value: '', text: 'every estate' }),
    ...(estates || []).map((e) => el('option', { value: String(e.id), text: e.name })));

  const dayBoxes = DAYS.map((d, i) => {
    const cb = el('input', { type: 'checkbox' });
    cb.checked = true;
    return { cb, bit: 1 << i, label: el('label', { class: 'dim tiny' }, cb, ' ' + d) };
  });

  async function create() {
    let mask = 0;
    for (const d of dayBoxes) if (d.cb.checked) mask |= d.bit;
    const [h, m] = (time.value || '03:00').split(':').map(Number);
    try {
      await api.post('/api/schedules', {
        name: name.value.trim() || (kind.value + ' ' + (time.value || '03:00')),
        kind: kind.value,
        minute_of_day: (h * 60) + m,
        weekdays: mask,
        tz: tz.value.trim() || 'UTC',
        jitter_minutes: Number(jitter.value) || 0,
        estate_id: estate.value ? Number(estate.value) : 0,
      });
      toast('Schedule created.', 'good');
      route();
    } catch (e) { toast(e.message, 'bad'); }
  }

  const form = el('div', { class: 'form', style: 'flex-wrap:wrap;gap:.6rem;align-items:center' },
    name, kind,
    el('span', { class: 'dim tiny', text: 'at' }), time, tz,
    el('span', { class: 'dim tiny', text: 'stagger (min)' }), jitter,
    estate,
    ...dayBoxes.map((d) => d.label),
    el('button', { onclick: create }, 'Create schedule'));

  const rows = (list || []).map((s) => el('tr', {},
    el('td', {}, el('div', { text: s.name || '(unnamed)' }),
      el('div', { class: 'dim tiny mono', text: s.kind })),
    el('td', { class: 'mono', text: hhmm(s.minute_of_day) + ' ' + s.tz }),
    el('td', { class: 'tiny', text: weekdaysText(s.weekdays) }),
    el('td', { class: 'tiny', text: s.agent_id ? 'one host' : (s.estate_id ? 'estate ' + s.estate_id : 'all hosts') }),
    el('td', { class: 'tiny dim', text: s.jitter_minutes ? '±' + s.jitter_minutes + ' min' : 'none' }),
    el('td', { class: 'tiny' }, el('div', { text: s.next_run ? new Date(s.next_run).toLocaleString() : '—' }),
      el('div', { class: 'dim', text: s.last_run && !s.last_run.startsWith('0001') ? 'last ' + ago(s.last_run) : 'never run' })),
    el('td', {}, el('span', { class: s.enabled ? 'st-online' : 'dim', text: s.enabled ? 'enabled' : 'paused' })),
    el('td', {}, el('div', { class: 'actions' },
      el('button', { class: 'ghost', onclick: async () => {
        try { await api.post('/api/schedules/' + s.id + '/enabled', { enabled: !s.enabled }); route(); }
        catch (e) { toast(e.message, 'bad'); }
      } }, s.enabled ? 'Pause' : 'Resume'),
      el('button', { class: 'danger', onclick: async () => {
        if (!confirm('Delete this schedule?')) return;
        try { await api.post('/api/schedules/' + s.id + '/delete', {}); toast('Deleted.', 'good'); route(); }
        catch (e) { toast(e.message, 'bad'); }
      } }, 'Delete')))));

  render(
    panel('Scheduled scans',
      el('p', { class: 'dim', style: 'padding:0 1rem' },
        'Monitoring evaluates what changes; a full sweep is the expensive operation and runs when asked. '
        + 'A schedule lets that be a clock rather than a person, so deep scans land in the small hours. '
        + 'Starts are staggered across the window: beginning a sweep on every host at the same instant is '
        + 'a self-inflicted outage on shared hosting. Only scan, baseline and verify can be scheduled — '
        + 'nothing that deletes or kills runs unattended.'),
      form,
      table(['Schedule', 'Time', 'Days', 'Scope', 'Stagger', 'Next / last run', 'State', ''], rows)));
}

// --- commands --------------------------------------------------------------

function commandRow(c) {
  const needsApproval = c.status === 'pending' && c.requires_approval;
  return el('tr', {},
    el('td', { class: 'dim tiny', text: ago(c.created_at) }),
    el('td', {}, el('span', { class: 'mono', text: c.kind })),
    el('td', {}, el('span', { class: c.status === 'done' ? 'st-online' : c.status === 'failed' ? 'st-offline' : '', text: c.status })),
    el('td', { class: 'dim tiny', text: c.created_by + (c.approved_by ? ' → ' + c.approved_by : '') }),
    el('td', {},
      needsApproval && me.can_approve
        ? el('div', { class: 'actions' },
            el('button', { class: 'danger', onclick: () => approve(c.id) }, 'Approve'),
            el('button', { class: 'ghost', onclick: () => cancel(c.id) }, 'Cancel'))
        : el('span', { class: 'dim tiny', text: c.error || (c.result ? c.result.slice(0, 160) : '') })));
}

async function approve(id) {
  if (!confirm('Approve this command for dispatch?\n\nDestructive actions will begin at the agent’s next check-in.')) return;
  try { await api.post('/api/commands/' + encodeURIComponent(id) + '/approve', {}); toast('Approved.', 'good'); route(); }
  catch (e) { toast(e.message, 'bad'); }
}

async function cancel(id) {
  try { await api.post('/api/commands/' + encodeURIComponent(id) + '/cancel', {}); toast('Cancelled.', 'good'); route(); }
  catch (e) { toast(e.message, 'bad'); }
}

async function viewCommands() {
  const cmds = await api.get('/api/commands');
  const pending = cmds.filter((c) => c.status === 'pending');
  const rest = cmds.filter((c) => c.status !== 'pending');
  render(
    panel('Awaiting approval (' + pending.length + ')',
      table(['Created', 'Kind', 'Status', 'By', ''], pending.map(commandRow))),
    panel('History', table(['Created', 'Kind', 'Status', 'By', 'Detail'], rest.map(commandRow))));
}

// --- enrollment tokens ------------------------------------------------------

// Estates are customers. The important thing on this page is not the list —
// it is the installer button, because that is what turns "we bought a tool"
// into "the estate is actually covered".
//
// A site administrator at a customer should not have to be walked through
// copying a token, composing a command line, and getting a server address
// right. They get one file, they run it, the host appears here.
async function viewEstates() {
  const estates = await api.get('/api/estates');
  const out = el('div', {});

  // --- create ---------------------------------------------------------
  const name = el('input', { placeholder: 'e.g. Acme Hospitality Ltd' });
  const notes = el('input', { placeholder: 'optional — retainer, contact, ticket ref' });
  const createPanel = can('estates.manage') ? panel('New customer',
    el('p', { class: 'dim', style: 'padding:0 1rem' },
      'One estate per customer. Agents installed with that estate’s installer are filed under it automatically, and cross-site consensus only ever compares a customer against its own sites.'),
    el('div', { class: 'form' },
      el('label', {}, 'Name', name),
      el('label', {}, 'Notes', notes),
      el('button', {
        onclick: async () => {
          try {
            await api.post('/api/estates', { name: name.value, notes: notes.value });
            toast('Estate created.', 'good');
            viewEstates();
          } catch (e) { toast(e.message, 'bad'); }
        },
      }, 'Create estate'))) : null;

  // --- per-estate installer -------------------------------------------
  function installerControls(est) {
    const platform = el('select', {},
      el('option', { value: 'linux-amd64' }, 'Linux x86-64'),
      el('option', { value: 'linux-arm64' }, 'Linux ARM64'));
    const label = el('input', { placeholder: 'optional host label' });
    const uses = el('input', { type: 'number', value: '1', min: '1', max: '500', style: 'width:5rem' });
    const ttl = el('input', { type: 'number', value: '72', min: '1', max: '720', style: 'width:5rem' });
    const monitor = el('input', { type: 'checkbox', checked: true });
    const status = el('div', { class: 'dim tiny' });

    const btn = el('button', {
      onclick: async () => {
        btn.disabled = true;
        status.textContent = 'Building installer…';
        try {
          const fname = await download('/api/estates/' + est.id + '/installer', {
            platform: platform.value,
            label: label.value,
            monitor: monitor.checked,
            uses: Number(uses.value) || 1,
            ttl_hours: Number(ttl.value) || 72,
          }, 'wordeye-installer');
          status.textContent = 'Downloaded ' + fname + ' — send it to the site administrator; they run it with no arguments.';
          toast('Installer generated.', 'good');
        } catch (e) {
          status.textContent = '';
          toast(e.message, 'bad');
        } finally {
          btn.disabled = false;
        }
      },
    }, 'Generate installer');

    return el('div', { class: 'form' },
      el('label', {}, 'Platform', platform),
      el('label', {}, 'Host label', label),
      el('label', {}, 'Hosts', uses),
      el('label', {}, 'Enrollment window (hours)', ttl),
      el('label', { class: 'inline' }, monitor, ' Keep monitoring after the first scan'),
      btn, status,
      // The distinction matters and is not obvious from the field name: this
      // bounds how long the FILE can be used to join, not how long the agent
      // stays connected.
      el('p', { class: 'dim tiny', style: 'margin:0' },
        'The window is how long this installer can still enroll a host. Once a host ' +
        'has enrolled it keeps its own credential and stays connected indefinitely — ' +
        'the window expiring does not disconnect it. Use “Retire agent” to revoke access.'));
  }

  const rows = estates.map((e) => {
    const detail = el('tr', { class: 'hidden' }, el('td', { colspan: '5' },
      can('installer.generate')
        ? installerControls(e)
        : el('p', { class: 'dim', style: 'padding:0 1rem' },
            'Generating installers requires an administrator role.')));

    return [
      el('tr', {},
        el('td', {}, el('a', { href: '#/fleet/' + e.id, text: e.name }),
          e.notes ? el('div', { class: 'dim tiny', text: e.notes }) : null),
        el('td', { class: 'mono tiny dim', text: e.slug }),
        el('td', { class: 'num' },
          (e.agents ?? 0) > 0
            ? el('a', { href: '#/fleet/' + e.id, text: String(e.agents) })
            : el('span', { class: 'dim', text: '0' })),
        el('td', { class: 'dim tiny', text: e.created_at ? new Date(e.created_at).toLocaleDateString() : '' }),
        el('td', {},
          el('button', {
            class: 'ghost',
            onclick: () => detail.classList.toggle('hidden'),
          }, 'Installer'))),
      detail,
    ];
  }).flat();

  render(
    createPanel,
    panel('Customers',
      estates.length
        ? el('table', {},
            el('thead', {}, el('tr', {},
              el('th', {}, 'Customer'), el('th', {}, 'Slug'),
              el('th', { class: 'num' }, 'Agents'), el('th', {}, 'Created'), el('th', {}, ''))),
            el('tbody', {}, ...rows))
        : el('div', { class: 'empty', text: 'No customers yet. Create one above, then generate an installer for it.' })),
    out);
}

async function viewTokens() {
  const toks = await api.get('/api/tokens');
  const label = el('input', { placeholder: 'e.g. Acme production' });
  const uses = el('input', { type: 'number', value: '1', min: '1', max: '500' });
  const ttl = el('input', { type: 'number', value: '24', min: '1', max: '8760' });
  const contain = el('input', { type: 'checkbox' });
  const out = el('div', {});

  const create = el('button', {
    onclick: async () => {
      try {
        const d = await api.post('/api/tokens', {
          label: label.value,
          uses: Number(uses.value) || 1,
          ttl_hours: Number(ttl.value) || 24,
          allow_remote_contain: contain.checked,
        });
        clear(out).append(
          el('p', { class: 'warn', text: 'Copy this now — it is not stored and cannot be shown again.' }),
          el('pre', { class: 'evidence', text: d.token }),
          el('p', { class: 'dim tiny', text: 'Enroll an agent with:' }),
          el('pre', { class: 'evidence', text: 'wordeye-agent enroll --server ' + location.origin.replace(/:\d+$/, ':8444') + ' --token ' + d.token + (contain.checked ? ' --allow-remote-contain' : '') }));
        viewTokens();
      } catch (e) { toast(e.message, 'bad'); }
    },
  }, 'Create token');

  const rows = toks.map((t) => el('tr', {},
    el('td', { class: 'mono tiny', text: t.prefix + '…' }),
    el('td', { text: t.label || '—' }),
    el('td', { class: 'num', text: t.uses_consumed + '/' + t.uses_allowed }),
    el('td', { class: 'dim tiny', text: t.expires_at ? new Date(t.expires_at).toLocaleString() : 'never' }),
    el('td', {}, t.allow_remote_contain
      ? el('span', { class: 'st-offline', text: 'grants containment' })
      : el('span', { class: 'dim', text: 'detection only' })),
    el('td', {}, t.revoked
      ? el('span', { class: 'dim', text: 'revoked' })
      : el('button', {
          class: 'ghost',
          onclick: async () => {
            try { await api.post('/api/tokens/' + t.id + '/revoke', {}); toast('Revoked.', 'good'); viewTokens(); }
            catch (e) { toast(e.message, 'bad'); }
          },
        }, 'Revoke'))));

  render(
    panel('New enrollment token',
      el('p', { class: 'dim', style: 'padding:0 1rem' },
        'A raw token, for hosts you enroll by hand. For rolling out to a customer, prefer '),
      el('p', { style: 'padding:0 1rem' },
        el('a', { href: '#/estates', text: 'Estates → Generate installer' }),
        el('span', { class: 'dim', text: ' — that produces a single file the site administrator runs with no arguments, and files the host under the right customer automatically.' })),
      el('p', { class: 'dim', style: 'padding:0 1rem' },
        'An agent can only join the fleet with a token issued here. Granting containment lets an agent enrolled with this token accept destructive orders — the agent must also opt in with --allow-remote-contain.'),
      el('div', { class: 'form' },
        el('label', {}, 'Label', label),
        el('label', {}, 'Uses', uses),
        el('label', {}, 'Expires (hours)', ttl),
        el('label', { class: 'inline' }, contain, ' Grant remote containment'),
        create),
      out),
    panel('Tokens', table(['Prefix', 'Label', 'Uses', 'Expires', 'Capability', ''], rows)));
}

// --- users -----------------------------------------------------------------

async function viewUsers() {
  const users = await api.get('/api/users');
  const u = el('input', { placeholder: 'username' });
  const p = el('input', { type: 'password', placeholder: 'password (min 12 chars)' });
  const role = el('select', {}, ...['operator', 'admin', 'viewer'].map((r) => el('option', { value: r, text: r })));

  const rows = users.map((x) => el('tr', {},
    el('td', { text: x.username }),
    el('td', { class: 'dim', text: x.role }),
    el('td', {}, x.totp_enrolled
      ? el('span', { class: 'st-online', text: 'enrolled' })
      : el('span', { class: 'st-offline', text: 'not set up' })),
    el('td', { class: 'dim tiny', text: ago(x.last_login) }),
    el('td', {}, x.disabled ? el('span', { class: 'st-offline', text: 'disabled' }) : el('span', { class: 'dim', text: 'active' })),
    el('td', {}, el('div', { class: 'actions' },
      el('button', {
        class: 'ghost',
        onclick: async () => {
          if (!confirm('Reset this user’s second factor?\n\nThey will re-enroll on next sign-in, and all their sessions are revoked. This is the only way to bypass MFA, so it is prominently audited.')) return;
          try { await api.post('/api/users/' + x.id + '/reset-mfa', {}); toast('MFA reset.', 'good'); viewUsers(); }
          catch (e) { toast(e.message, 'bad'); }
        },
      }, 'Reset MFA'),
      el('button', {
        class: 'ghost',
        onclick: async () => {
          try { await api.post('/api/users/' + x.id + '/disable', { disabled: !x.disabled }); viewUsers(); }
          catch (e) { toast(e.message, 'bad'); }
        },
      }, x.disabled ? 'Enable' : 'Disable')))));

  render(
    panel('Add operator', el('div', { class: 'form' }, u, p, role,
      el('button', {
        onclick: async () => {
          try {
            await api.post('/api/users', { username: u.value, password: p.value, role: role.value });
            p.value = ''; u.value = '';
            toast('Created. They will set up MFA on first sign-in.', 'good');
            viewUsers();
          } catch (e) { toast(e.message, 'bad'); }
        },
      }, 'Create'))),
    panel('Operators', table(['User', 'Role', 'MFA', 'Last sign-in', 'Status', ''], rows)));
}

// --- audit -----------------------------------------------------------------

async function viewAudit() {
  const entries = await api.get('/api/audit?limit=300');
  const rows = entries.map((a) => el('tr', {},
    el('td', { class: 'dim tiny', text: new Date(a.at).toLocaleString() }),
    el('td', { text: a.actor }),
    el('td', { class: 'mono tiny', text: a.action }),
    el('td', { class: 'mono tiny', text: a.target }),
    el('td', {}, a.result === 'ok'
      ? el('span', { class: 'st-online', text: 'ok' })
      : el('span', { class: 'st-offline', text: a.result })),
    el('td', { class: 'dim tiny', text: a.detail })));

  render(panel('Audit log',
    el('p', { class: 'dim', style: 'padding:0 1rem' },
      'Append-only. Every sign-in, approval and destructive order is recorded here.'),
    table(['When', 'Actor', 'Action', 'Target', 'Result', 'Detail'], rows)));
}

boot();
