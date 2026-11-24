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
function inline(parent, text) {
  // **bold** and `code`; everything else is plain text
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
    const tok = m[0];
    parent.appendChild(tok.startsWith('**') ? el('strong', null, tok.slice(2, -2)) : el('code', null, tok.slice(1, -1)));
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
    const auth = checkbox('I own this site or am authorized to test it', false);
    const hint = el('div', 'hint');
    const check = () => {
      const host = hostOf(target.value.trim());
      const allowed = host && allowedHosts.some((h) => h === host || h === host.split(':')[0]);
      hint.textContent = !host ? 'Enter a full URL (https://...).'
        : (allowed || !allowedHosts.length ? '' : host + ' is not in Allowed targets: the scanner will refuse it.');
    };
    target.addEventListener('input', check);
    check();
    node.append(field('Target', target), list, profileField(profile), auth.wrap, hint);
    return {
      node,
      run: 'Run scan',
      ready: () => auth.box.checked && !!hostOf(target.value.trim()) && profileOk(profile),
      watch: [auth.box, target, profile],
      collect: () => ({ ...args, target_url: target.value.trim(), profile: profile.value }),
    };
  }
  if (req.name === 'start_demo_scan') {
    const profile = profileSelect(args.profile || 'quick');
    const signIn = checkbox('Sign in with the demo app\'s fake account (admin role)', !!args.sign_in);
    node.append(el('p', 'hint', 'The built-in, deliberately vulnerable demo app on this machine.'),
      profileField(profile), signIn.wrap);
    return { node, run: 'Run demo scan', ready: () => profileOk(profile), watch: [profile],
      collect: () => ({ ...args, profile: profile.value, sign_in: signIn.box.checked }) };
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

async function send(text) {
  stickToBottom = true; // sending always brings you back to the latest
  add(el('div', 'msg user', text));
  sendBtn.disabled = true;
  const r = await api('POST', 'send', { thread_id: threadId, message: text });
  if (!r.ok) {
    add(el('div', 'line err', r.data.error || ('error ' + r.status)));
    sendBtn.disabled = sendLocked();
    return;
  }
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
      conn.title = 'Allowlisted: ' + (Array.isArray(d.allowlisted) ? d.allowlisted.join(', ') : d.allowlisted)
        + (d.scanner_llm === false ? ' · scanner without LLM steps' : '');
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
