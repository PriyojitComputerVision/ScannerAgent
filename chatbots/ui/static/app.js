// ScopeGuard MCP chatbot UI. No inline code, no HTML sinks: every node is built with
// createElement/textContent, because answers quote text from scanned sites.
'use strict';

const log = document.getElementById('log');
const input = document.getElementById('input');
const sendBtn = document.getElementById('send');
const conn = document.getElementById('conn');

let threadId = crypto.randomUUID();
let cursor = 0;        // next event index for this thread
let polling = false;
let streamBubble = null;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---------------------------------------------------------------- auto scroll
// <main> is the only scrolling area. New content keeps it at the bottom while you are
// there; if you scroll up to read, it stays put and offers "Jump to latest".
const scroller = document.querySelector('main');
const jump = document.getElementById('jump-latest');
let stickToBottom = true;

function nearBottom() {
  return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80;
}

function follow(force) {
  if (force) stickToBottom = true;
  if (!stickToBottom) {
    jump.hidden = false;
    return;
  }
  // Reading scrollHeight forces layout, so this is exact without waiting for a frame
  // (frame callbacks pause in background tabs).
  scroller.scrollTop = scroller.scrollHeight;
  jump.hidden = true;
}

scroller.addEventListener('scroll', () => {
  stickToBottom = nearBottom();
  if (stickToBottom) jump.hidden = true;
});
jump.addEventListener('click', () => follow(true));
// Anything that grows the chat (new cards, streamed tokens, cards filling in) is followed.
new MutationObserver(() => follow()).observe(log, { childList: true, subtree: true, characterData: true });

function add(node) {
  log.appendChild(node);
  follow();
  return node;
}

async function api(method, name, body, query) {
  const url = '/api/' + name + (query ? '?' + new URLSearchParams(query) : '');
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  return { ok: res.ok, status: res.status, data };
}

// ---------------------------------------------------------------- tiny safe Markdown
// Only scan report files are links: /reports/<session id>/report.<ext>, opened through this
// page's own origin (serve_ui.py fetches them with the chatbot's token). Any other URL stays text.
const REPORT_PATH = /^\/reports\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\/(report\.(?:html|md|json|docx))$/;

function reportHref(url) {
  let path;
  try { path = new URL(url, window.location.origin).pathname; } catch (e) { return null; }
  const m = REPORT_PATH.exec(path);
  if (!m || m[1].includes('..')) return null;
  return '/reports/' + encodeURIComponent(m[1]) + '/' + m[2];
}

function reportLink(label, href) {
  const a = el('a', 'report-link', label);
  a.href = href;
  a.rel = 'noopener noreferrer';
  if (href.endsWith('.html')) {
    a.target = '_blank';
  } else {
    a.setAttribute('download', '');
  }
  return a;
}

function inline(parent, text) {
  // **bold**, `code` and [label](report link); everything else is plain text
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]\n]{1,120}\]\([^)\s]{1,600}\))/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
    const tok = m[0];
    if (tok.startsWith('**')) {
      parent.appendChild(el('strong', null, tok.slice(2, -2)));
    } else if (tok.startsWith('`')) {
      parent.appendChild(el('code', null, tok.slice(1, -1)));
    } else {
      const split = tok.indexOf('](');
      const label = tok.slice(1, split);
      const href = reportHref(tok.slice(split + 2, -1));
      parent.appendChild(href ? reportLink(label, href) : document.createTextNode(tok));
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
}

function cells(row) {
  return row.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
}

function renderMarkdown(text) {
  const root = el('div');
  const lines = text.replace(/\r/g, '').split('\n');
  let list = null;
  let para = null;
  const flush = () => { list = null; para = null; };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) { flush(); continue; }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      flush();
      const node = el(h[1].length <= 2 ? 'h3' : 'h4');
      inline(node, h[2]);
      root.appendChild(node);
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1])) {
      flush();
      const table = el('table');
      const head = el('tr');
      cells(line).forEach((c) => { const th = el('th'); inline(th, c); head.appendChild(th); });
      table.appendChild(head);
      i += 1;
      while (i + 1 < lines.length && /^\s*\|.*\|\s*$/.test(lines[i + 1])) {
        i += 1;
        const tr = el('tr');
        cells(lines[i]).forEach((c) => { const td = el('td'); inline(td, c); tr.appendChild(td); });
        table.appendChild(tr);
      }
      root.appendChild(table);
      continue;
    }
    const li = /^\s*(?:[-*]|\d+\.)\s+(.*)$/.exec(line);
    if (li) {
      para = null;
      const ordered = /^\s*\d+\./.test(line);
      if (!list || list.tagName !== (ordered ? 'OL' : 'UL')) {
        list = el(ordered ? 'ol' : 'ul');
        root.appendChild(list);
      }
      const item = el('li');
      inline(item, li[1]);
      list.appendChild(item);
      continue;
    }
    list = null;
    if (!para) { para = el('p'); root.appendChild(para); } else { para.appendChild(document.createTextNode(' ')); }
    inline(para, line.trim());
  }
  return root;
}

// ---------------------------------------------------------------- events
function short(obj) {
  const s = JSON.stringify(obj);
  return s.length > 300 ? s.slice(0, 300) + '…' : s;
}

// ---------------------------------------------------------------- approval cards (option based)
// Only the pentest-agent's four scan profiles (the console offers the same). Whether each
// is allowed for this chatbot's role, and its description, come from the scanner's
// scan_policy; anything else a server might list is ignored.
const PROFILE_NAMES = { quick: 'Quick', standard: 'Standard', aggressive: 'Aggressive', auth_deep: 'Auth deep' };
let scannerProfiles = Object.keys(PROFILE_NAMES).map((p) => ({ profile: p, allowed: true, description: '' }));
let allowedHosts = []; // filled by the Allowed targets bar
let chatRoles = [];    // the chatbot's token roles (from /api/info): admin unlocks sign-in and code uploads
const isAdmin = () => chatRoles.includes('admin');
const ADMIN_HINT = 'needs the chatbot to run as admin: set CHATBOT_ROLES=admin in chatbots/mcp_chatbot/.env and restart';

async function loadProfiles() {
  for (let i = 0; i < 60; i++) {
    const r = await api('GET', 'policy');
    if (r.ok && Array.isArray(r.data.profiles)) {
      const known = r.data.profiles.filter((p) => Object.prototype.hasOwnProperty.call(PROFILE_NAMES, p.profile));
      if (known.length) scannerProfiles = known;
      return;
    }
    await new Promise((res) => setTimeout(res, 2000));
  }
}
let formSeq = 0;

function button(label, cls) {
  const b = el('button', cls || null, label);
  b.type = 'button';
  return b;
}

function field(labelText, control) {
  const wrap = el('label', 'field');
  wrap.appendChild(el('span', 'field-label', labelText));
  wrap.appendChild(control);
  return wrap;
}

function profileSelect(current) {
  const sel = el('select');
  const wanted = current || 'standard';
  scannerProfiles.forEach((p) => {
    // Short labels keep the dropdown inside the card; the description shows below it.
    const opt = el('option', null, PROFILE_NAMES[p.profile] + (p.allowed ? '' : ' (needs admin)'));
    opt.value = p.profile;
    opt.disabled = !p.allowed;
    sel.appendChild(opt);
  });
  const usable = scannerProfiles.filter((p) => p.allowed).map((p) => p.profile);
  sel.value = usable.indexOf(wanted) >= 0 ? wanted : (usable.indexOf('standard') >= 0 ? 'standard' : usable[0] || '');
  return sel;
}

// Profile dropdown plus a one-line description of the selected profile under it.
function profileField(sel) {
  const wrap = field('Profile', sel);
  const desc = el('div', 'desc');
  const show = () => {
    const p = scannerProfiles.find((x) => x.profile === sel.value);
    desc.textContent = p && p.description ? p.description : '';
  };
  sel.addEventListener('change', show);
  show();
  wrap.appendChild(desc);
  return wrap;
}

// What the scan tests (human in the loop: you decide in the approval card). Code scopes need
// source code in the request (an attached .zip or a git link) and the admin role.
const SCOPES = [
  { value: 'website_and_code', label: 'Website + source code', desc: 'The site, then your code (sandbox). One report.' },
  { value: 'website', label: 'Website only', desc: 'The site only; any attached code is left out.' },
  { value: 'code', label: 'Source code only', desc: 'Only your code (sandbox). No request is sent to the site; its URL only labels the report.' },
];

function scopeSelect(args) {
  const sel = el('select');
  const hasCode = !!(args.upload_id || args.git_url);
  SCOPES.forEach((s) => {
    const codeScope = s.value !== 'website';
    const opt = el('option', null, s.label + (codeScope && !hasCode ? ' (attach code first)' : ''));
    opt.value = s.value;
    opt.disabled = codeScope && (!hasCode || !isAdmin());
    sel.appendChild(opt);
  });
  const wanted = SCOPES.some((s) => s.value === args.scan_scope) ? args.scan_scope : (hasCode ? 'website_and_code' : 'website');
  const usable = Array.from(sel.options).filter((o) => !o.disabled).map((o) => o.value);
  sel.value = usable.indexOf(wanted) >= 0 ? wanted : 'website';
  return sel;
}

function scopeField(sel, args) {
  const wrap = field('What to test', sel);
  const desc = el('div', 'desc');
  const show = () => {
    const s = SCOPES.find((x) => x.value === sel.value);
    desc.textContent = s ? s.desc : '';
    if (!(args.upload_id || args.git_url)) desc.textContent += ' To include code: attach a .zip (+ Code) or give a public .git link.';
    else if (!isAdmin()) desc.textContent += ' Code scopes ' + ADMIN_HINT + '.';
  };
  sel.addEventListener('change', show);
  show();
  wrap.appendChild(desc);
  return wrap;
}

function profileOk(sel) {
  return scannerProfiles.some((p) => p.profile === sel.value && p.allowed);
}

function checkbox(text, checked) {
  const wrap = el('label', 'check');
  const box = el('input');
  box.type = 'checkbox';
  box.checked = !!checked;
  wrap.appendChild(box);
  wrap.appendChild(el('span', null, text));
  return { wrap, box };
}

function hostOf(url) {
  try { return new URL(url).host; } catch (e) { return ''; }
}

// Builds the form for one request; returns {node, collect()} where collect() gives the
// args to run with, or null when the form is not complete.
function approvalForm(req) {
  const args = req.args || {};
  const node = el('div', 'form');
  if (req.name === 'start_scan') {
    const target = el('input');
    target.value = args.target_url || '';
    target.placeholder = 'https://your-site.example/';
    const listId = 'targets-' + (++formSeq);
    const list = el('datalist');
    list.id = listId;
    allowedHosts.forEach((h) => { const o = el('option'); o.value = 'https://' + h + '/'; list.appendChild(o); });
    target.setAttribute('list', listId);
    const profile = profileSelect(args.profile);
    const scope = scopeSelect(args);
    const auth = checkbox('I own this site (and the code, if any) or am authorized to test it', false);
    const hint = el('div', 'hint');
    const check = () => {
      const host = hostOf(target.value.trim());
      const allowed = host && allowedHosts.some((h) => h === host || h === host.split(':')[0]);
      const codeOnly = scope.value === 'code';
      target.placeholder = codeOnly ? 'optional for code only (labels the report)' : 'https://your-site.example/';
      hint.textContent = !host ? (codeOnly && !target.value.trim() ? '' : 'Enter a full URL (https://...).')
        : (allowed || !allowedHosts.length ? '' : host + ' is not in Allowed targets: the scanner will refuse it.');
    };
    target.addEventListener('input', check);
    scope.addEventListener('change', check);
    check();
    node.append(field('Target', target), list, scopeField(scope, args), profileField(profile), auth.wrap, hint);
    return {
      node,
      run: 'Run scan',
      ready: () => auth.box.checked && (scope.value === 'code' || !!hostOf(target.value.trim())) && profileOk(profile)
        && !scope.options[scope.selectedIndex].disabled,
      watch: [auth.box, target, profile, scope],
      collect: () => {
        const out = { ...args, target_url: target.value.trim(), profile: profile.value, scan_scope: scope.value };
        // Website only: the code is not part of this scan (the scanner refuses the mix).
        if (scope.value === 'website') { delete out.upload_id; delete out.git_url; delete out.git_ref; }
        // Code only: no website needed; an empty target is left out.
        if (scope.value === 'code' && !out.target_url) delete out.target_url;
        return out;
      },
    };
  }
  if (req.name === 'start_demo_scan') {
    const profile = profileSelect(args.profile || 'quick');
    // Signing in is an authenticated scan (scan:authenticated): only offered when the chatbot is admin.
    const signIn = checkbox(isAdmin() ? 'Also sign in with the demo app\'s public, fake account (authenticated scan)'
      : 'Sign in with the demo app\'s fake account: ' + ADMIN_HINT, isAdmin() && !!args.sign_in);
    signIn.box.disabled = !isAdmin();
    if (!isAdmin()) signIn.wrap.classList.add('disabled');
    node.append(el('p', 'hint', 'The built-in, deliberately vulnerable demo app on this machine.'),
      profileField(profile), signIn.wrap);
    return { node, run: 'Run demo scan', ready: () => profileOk(profile), watch: [profile],
      collect: () => ({ ...args, profile: profile.value, sign_in: isAdmin() && signIn.box.checked }) };
  }
  if (req.name === 'cancel_scan') {
    node.append(el('p', null, 'Stop scan ' + (args.scan_id || '') + ' after its current step?'));
    return { node, run: 'Yes, stop it', ready: () => true, watch: [], collect: () => args };
  }
  node.append(el('p', null, req.description || ''));
  return { node, run: 'Approve', ready: () => true, watch: [], collect: () => args };
}

function showApproval(requests) {
  const answers = new Array(requests.length).fill(null);
  const box = add(el('div', 'approval'));
  const titles = { start_scan: 'Scan a website', start_demo_scan: 'Scan the demo app', cancel_scan: 'Cancel a scan' };
  requests.forEach((req, idx) => {
    const part = el('div', 'approval-part');
    part.appendChild(el('h3', null, titles[req.name] || ('Approve ' + req.name)));
    const form = approvalForm(req);
    part.appendChild(form.node);

    const details = el('details', 'line');
    details.appendChild(el('summary', null, 'details (what the assistant asked for)'));
    details.appendChild(el('pre', null, JSON.stringify(req.args, null, 2)));
    part.appendChild(details);

    const actions = el('div', 'actions');
    const run = button(form.run);
    const cancel = button(req.name === 'cancel_scan' ? 'No' : 'Cancel', 'danger');
    actions.append(run, cancel);
    part.appendChild(actions);
    const refresh = () => { run.disabled = !form.ready(); };
    form.watch.forEach((c) => { c.addEventListener('input', refresh); c.addEventListener('change', refresh); });
    refresh();

    const settle = (answer, label) => {
      answers[idx] = answer;
      part.querySelectorAll('input, select, button').forEach((c) => { c.disabled = true; });
      actions.replaceChildren(el('span', 'done', label));
      if (answers.every((a) => a !== null)) submitDecisions(answers);
    };
    run.addEventListener('click', () => {
      if (!form.ready()) return;
      // Sent as an edit: the chosen options are what runs. For start_scan the
      // backend also sets authorization_confirmed=true, because you ticked the box.
      settle({ type: 'edit', args: form.collect() }, form.run + ': started');
    });
    cancel.addEventListener('click', () => settle({ type: 'reject', message: 'The user cancelled this in the UI.' },
      'Cancelled'));
    box.appendChild(part);
  });
}

// ---------------------------------------------------------------- sign-in pause (SSO / MFA)
// A scan waits for the user (human in the loop). The answer goes from this page to the
// scanner's MCP submit_sign_in / skip_sign_in directly: codes never pass through the model.
const SVG_NS = 'http://www.w3.org/2000/svg';
function eyeIcon(open) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const shape = (tag, attrs) => {
    const n = document.createElementNS(SVG_NS, tag);
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
    n.setAttribute('fill', 'none');
    n.setAttribute('stroke', 'currentColor');
    n.setAttribute('stroke-width', '1.8');
    svg.appendChild(n);
  };
  shape('path', { d: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z' });
  shape('circle', { cx: '12', cy: '12', r: '3' });
  if (!open) shape('path', { d: 'M3 3l18 18' });
  return svg;
}

// A secret input with an eye button: crossed eye = hidden, open eye = shown.
function secretInput(placeholder, maxLength, visibleByDefault) {
  const wrap = el('span', 'secret-field');
  const input = el('input');
  input.maxLength = maxLength;
  input.placeholder = placeholder;
  input.autocomplete = 'off';
  input.spellcheck = false;
  const eye = button('', 'reveal');
  const show = (on) => {
    input.type = on ? 'text' : 'password';
    eye.setAttribute('aria-pressed', on ? 'true' : 'false');
    eye.setAttribute('aria-label', on ? 'Hide' : 'Show');
    eye.title = on ? 'Hide' : 'Show';
    eye.replaceChildren(eyeIcon(!on));
  };
  eye.addEventListener('click', () => { show(input.type === 'password'); input.focus(); });
  show(Boolean(visibleByDefault));
  wrap.append(input, eye);
  return { wrap, input, hide: () => show(Boolean(visibleByDefault)) };
}

let activeSignIn = null; // the card waiting for an answer (Esc skips it)

function safeHttpUrl(raw) {
  try {
    const u = new URL(raw);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
  } catch (e) { return null; }
}

function showSignIn(req) {
  streamBubble = null;
  const kind = req.kind === 'mfa' ? 'mfa' : (req.kind === 'sso' ? 'sso' : 'session');
  const box = add(el('div', 'approval signin'));
  box.appendChild(el('h3', null, kind === 'mfa' ? 'Enter your one-time code'
    : (kind === 'sso' ? 'SSO sign-in needed' : 'Sign-in needed')));
  box.appendChild(el('p', null, 'Scan ' + (req.scan_id || '') + ' is waiting for you (human in the loop). '
    + (req.evidence ? 'Why: ' + req.evidence + '. ' : '')
    + 'No answer within ' + (req.timeout_seconds || 300) + ' s = skipped.'));
  if (req.methods && req.methods.length) {
    box.appendChild(el('p', 'line', 'The site signs in with: ' + req.methods.join(' and ')));
  }
  if (req.idp_host) box.appendChild(el('p', 'line', 'Identity provider: ' + req.idp_host));
  const href = safeHttpUrl(req.login_url);
  if (href && kind !== 'mfa') {
    // A page cannot open a tab without a click, so this is a link the user opens.
    const a = el('a', 'btn-link', 'Open the sign-in page in a new tab');
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    box.appendChild(a);
  }
  let secret;
  if (kind === 'mfa') {
    secret = secretInput('123456', 12, false);
    box.appendChild(field('One-time code', secret.wrap));
  } else {
    box.appendChild(el('p', 'line', 'Sign in in that tab (SSO, MFA and all). The operator then stores the session '
      + 'once: uv run scopeguard-mcp credentials add NAME --target HOST --session. Enter that profile name below. '
      + 'Never paste passwords here.'));
    secret = secretInput('session profile name', 64, true);
    box.appendChild(field('Session credential profile', secret.wrap));
  }
  const status = el('p', 'line', '');
  const actions = el('div', 'actions');
  const go = button(kind === 'mfa' ? 'Send code' : 'Continue signed in');
  const skip = button('Skip: scan unauthenticated (Esc)', 'danger');
  actions.append(go, skip);
  box.append(actions, status);

  const send = async (body, label) => {
    go.disabled = true;
    skip.disabled = true;
    const r = await api('POST', 'sign_in', { thread_id: threadId, scan_id: req.scan_id, ...body });
    secret.input.value = '';
    secret.hide();
    if (r.ok) {
      activeSignIn = null;
      box.querySelectorAll('input, button').forEach((c) => { c.disabled = true; });
      actions.replaceChildren(el('span', 'done', label));
      status.textContent = '';
    } else {
      go.disabled = false;
      skip.disabled = false;
      status.textContent = (r.data && r.data.error) || 'The answer was not accepted.';
    }
  };
  const submit = () => {
    const value = secret.input.value.trim();
    if (!value) {
      status.textContent = kind === 'mfa' ? 'Enter the code first.' : 'Enter the profile name first.';
      return;
    }
    send(kind === 'mfa' ? { action: 'mfa_code', code: value } : { action: 'session', credentials: value },
      kind === 'mfa' ? 'Code sent' : 'Session sent');
  };
  go.addEventListener('click', submit);
  secret.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
  const doSkip = () => send({ action: 'skip' }, 'Skipped: the scan continues unauthenticated');
  skip.addEventListener('click', doSkip);
  activeSignIn = doSkip;
  secret.input.focus();
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && activeSignIn) { e.preventDefault(); activeSignIn(); }
});

function handle(ev) {
  switch (ev.type) {
    case 'token':
      if (!streamBubble) streamBubble = add(el('div', 'msg bot streaming', ''));
      streamBubble.textContent += ev.text;
      follow();
      break;
    case 'answer': {
      const bubble = streamBubble || add(el('div', 'msg bot'));
      bubble.className = 'msg bot';
      bubble.replaceChildren(renderMarkdown(ev.text));
      streamBubble = null;
      follow(); // the formatted answer is taller than the streamed text
      break;
    }
    case 'tool_call':
      streamBubble = null;
      add(el('div', 'line call', '→ ' + ev.name + ' ' + short(ev.args)));
      break;
    case 'progress':
      add(el('div', 'line progress', ev.text));
      break;
    case 'scan_result': {
      // Verified block from the scanner itself (not written by the model).
      const card = add(el('div', 'msg result'));
      card.appendChild(renderMarkdown(ev.markdown));
      break;
    }
    case 'tool_result': {
      const d = add(el('details', 'line' + (ev.status === 'error' ? ' err' : '')));
      d.appendChild(el('summary', null, (ev.status === 'error' ? '✕ ' : '← ') + ev.name + ' result'));
      d.appendChild(el('pre', null, ev.preview));
      break;
    }
    case 'approval':
      streamBubble = null;
      showApproval(ev.requests);
      break;
    case 'sign_in':
      showSignIn(ev.request || {});
      break;
    case 'error':
      if (ev.kind === 'rate_limit') {
        showLimitNotice(ev);
      } else {
        add(el('div', 'line err', ev.text));
      }
      break;
    default:
      break;
  }
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    for (;;) {
      const r = await api('GET', 'events', null, { thread_id: threadId, after: String(cursor) });
      if (!r.ok) {
        add(el('div', 'line err', r.data.error || ('error ' + r.status)));
        break;
      }
      r.data.events.forEach(handle);
      cursor = r.data.next;
      if (!r.data.busy) break;
      await new Promise((res) => setTimeout(res, 600));
    }
  } finally {
    polling = false;
    sendBtn.disabled = sendLocked(); // stays off while a Groq limit counts down
  }
}

async function submitDecisions(answers) {
  const r = await api('POST', 'decide', { thread_id: threadId, answers });
  if (!r.ok) { add(el('div', 'line err', r.data.error || ('error ' + r.status))); return; }
  poll();
}

// ---------------------------------------------------------------- Groq limits
let blockedUntil = 0; // while a rate limit runs, Send stays disabled
let limitTimer = null;

function sendLocked() {
  return Date.now() < blockedUntil;
}

function clock(seconds) {
  const s = Math.max(0, Math.ceil(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const pad = (n) => String(n).padStart(2, '0');
  return h ? h + ':' + pad(m) + ':' + pad(s % 60) : m + ':' + pad(s % 60);
}

function showLimitNotice(ev) {
  const daily = ev.limit === 'TPD' || ev.limit === 'RPD';
  const box = add(el('div', 'notice'));
  box.appendChild(el('h3', null, daily ? 'Groq daily limit reached' : 'Groq rate limit reached'));
  box.appendChild(el('p', null, ev.text));
  const count = el('p', 'countdown');
  box.appendChild(count);
  box.appendChild(el('p', 'muted', daily
    ? 'Your scans and reports are not affected; only the chat model has to wait. Free-tier limits reset over the day.'
    : 'This clears within a minute.'));
  const wait = Number(ev.retry_after_seconds) || 0;
  if (!wait) { count.textContent = 'Try again a little later.'; return; }
  blockedUntil = Math.max(blockedUntil, Date.now() + wait * 1000);
  sendBtn.disabled = true;
  sendBtn.title = 'Waiting for the Groq limit to reset';
  if (limitTimer) clearInterval(limitTimer);
  const tick = () => {
    const left = (blockedUntil - Date.now()) / 1000;
    if (left <= 0) {
      clearInterval(limitTimer);
      limitTimer = null;
      count.textContent = 'You can send again now.';
      box.classList.add('cleared');
      sendBtn.title = '';
      if (!polling) sendBtn.disabled = false;
      return;
    }
    count.textContent = 'You can send again in ' + clock(left);
  };
  tick();
  limitTimer = setInterval(tick, 1000);
}

// ---------------------------------------------------------------- code attachment
const MAX_ZIP = 10 * 1024 * 1024;
const fileInput = document.getElementById('file');
const attachBtn = document.getElementById('attach');
const attBox = document.getElementById('attachment');
let attached = null; // {upload_id, filename}: sent with the next message

function showAttachment(att) {
  attached = att;
  attBox.hidden = !att;
  document.getElementById('att-name').textContent = att ? att.filename : '';
}

async function zipProblem(file) {
  if (!file) return 'Choose a .zip file.';
  if (!/\.zip$/i.test(file.name)) return 'Only .zip archives are accepted.';
  if (file.size === 0) return 'The archive is empty.';
  if (file.size > MAX_ZIP) {
    return 'The archive is ' + (file.size / 1048576).toFixed(1) + ' MB; at most ' + (MAX_ZIP / 1048576)
      + ' MB can be attached. Leave out node_modules, build output and data, then zip again.';
  }
  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  if (!(head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04)) return 'This is not a zip archive.';
  return '';
}

async function uploadZip(file) {
  const problem = await zipProblem(file);
  if (problem) { add(el('div', 'line err', problem)); return; }
  attachBtn.disabled = true;
  const note = add(el('div', 'line', 'Uploading ' + file.name + ' (' + Math.ceil(file.size / 1024) + ' KB)...'));
  try {
    const ctype = ['application/zip', 'application/x-zip-compressed'].includes(file.type) ? file.type : 'application/zip';
    const res = await fetch('/api/upload?' + new URLSearchParams({ thread_id: threadId, filename: file.name }),
      { method: 'POST', headers: { 'Content-Type': ctype }, body: file, credentials: 'same-origin' });
    let data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) throw new Error(data.error || ('error ' + res.status));
    note.textContent = 'Attached ' + data.filename + ' (sha256 ' + String(data.sha256 || '').slice(0, 12) + '). It goes with your next message.';
    showAttachment(data);
    input.focus();
  } catch (e) {
    note.className = 'line err';
    note.textContent = 'Upload failed: ' + e.message;
  } finally {
    attachBtn.disabled = !isAdmin();
    fileInput.value = '';
  }
}

attachBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => { if (fileInput.files.length) uploadZip(fileInput.files[0]); });
document.getElementById('att-remove').addEventListener('click', async () => {
  await api('POST', 'detach', { thread_id: threadId });
  showAttachment(null);
  add(el('div', 'line', 'Attachment removed.'));
});

async function send(text) {
  stickToBottom = true; // sending always brings you back to the latest
  add(el('div', 'msg user', attached ? text + '\n[attached: ' + attached.filename + ']' : text));
  sendBtn.disabled = true;
  const r = await api('POST', 'send', { thread_id: threadId, message: text });
  if (!r.ok) {
    add(el('div', 'line err', r.data.error || ('error ' + r.status)));
    sendBtn.disabled = sendLocked();
    return;
  }
  showAttachment(null); // the server attached it to this message
  poll();
}

document.getElementById('composer').addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text || sendBtn.disabled) return;
  input.value = '';
  send(text);
});
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    document.getElementById('composer').requestSubmit();
  }
});
document.getElementById('new-chat').addEventListener('click', () => {
  threadId = crypto.randomUUID();
  cursor = 0;
  streamBubble = null;
  while (log.children.length > 1) log.removeChild(log.lastChild);
  add(el('div', 'line', 'New conversation.'));
});

// ---------------------------------------------------------------- allowed targets
const allowList = document.getElementById('allow-list');
const allowForm = document.getElementById('allow-form');
const allowInput = document.getElementById('allow-input');
const allowStatus = document.getElementById('allow-status');

function setAllowStatus(text, isError) {
  allowStatus.textContent = text;
  allowStatus.className = 'allow-status' + (isError ? ' err' : '');
}

function renderAllowlist(data) {
  allowedHosts = data.hosts || [];
  const chips = [];
  (data.hosts || []).forEach((host) => {
    const chip = el('span', 'chip', host);
    if (data.editable) {
      const rm = el('button', null, '✕');
      rm.type = 'button';
      rm.title = 'Remove ' + host;
      rm.addEventListener('click', () => changeAllowlist({ remove: host }));
      chip.appendChild(rm);
    }
    chips.push(chip);
  });
  if (!chips.length) chips.push(el('span', 'chip none', 'none yet: only the demo app can be scanned'));
  allowList.replaceChildren(...chips);
  allowForm.hidden = !data.editable;
  if (!data.editable && data.note) setAllowStatus(data.note, false);
}

async function changeAllowlist(body) {
  const buttons = allowForm.querySelectorAll('button, input');
  buttons.forEach((b) => { b.disabled = true; });
  setAllowStatus('restarting the scanner with the new allowlist…', false);
  try {
    const r = await api('POST', 'allowlist', body);
    if (!r.ok) { setAllowStatus(r.data.error || ('error ' + r.status), true); return; }
    renderAllowlist(r.data);
    setAllowStatus('scanner ready', false);
    allowInput.value = '';
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

allowForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const host = allowInput.value.trim();
  if (host) changeAllowlist({ add: host });
});

async function loadAllowlist() {
  for (let i = 0; i < 60; i++) {
    const r = await api('GET', 'allowlist');
    if (r.ok) {
      renderAllowlist(r.data);
      if (r.data.editable || (r.data.note || '').indexOf('starting') < 0) return;
    }
    await new Promise((res) => setTimeout(res, 2000));
  }
}

async function info() {
  for (let i = 0; i < 120; i++) {
    const r = await api('GET', 'info');
    if (r.ok) {
      const d = r.data;
      conn.className = 'conn ok';
      conn.textContent = 'MCP ' + d.endpoint + ' · roles ' + (d.roles || []).join(',');
      chatRoles = Array.isArray(d.roles) ? d.roles.map(String) : [];
      attachBtn.disabled = !isAdmin();
      attachBtn.title = isAdmin() ? 'Attach source code (.zip, max 10 MB; analysed in the web scan; Python only for now, other files marked partial)'
        : 'Code uploads ' + ADMIN_HINT;
      const tools = d.tools || {};
      conn.title = 'Allowlisted: ' + (Array.isArray(d.allowlisted) ? d.allowlisted.join(', ') : d.allowlisted)
        + (d.scanner_llm === false ? ' · scanner without LLM steps' : '')
        + '\nTools on: ' + ((tools.enabled || []).join(', ') || 'none')
        + ((tools.disabled_here || []).length ? '\nSwitched off here: ' + tools.disabled_here.join(', ') : '')
        + ((tools.not_offered_by_server || []).length
          ? '\nNot offered by the server: ' + tools.not_offered_by_server.join(', ') : '');
      return;
    }
    conn.className = 'conn bad';
    conn.textContent = r.status === 401 ? 'session expired: restart serve_ui.py' : 'starting the chatbot…';
    if (r.status === 401) return;
    await new Promise((res) => setTimeout(res, 2000));
  }
}
info();
loadAllowlist();
loadProfiles();
