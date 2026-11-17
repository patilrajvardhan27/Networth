const $ = (id) => document.getElementById(id);
const COLS = ['Pro', 'Inside global', 'Inside local', 'Outside local', 'Outside global', 'TTL', 'State'];

// Fetched one admin endpoint and parsed it as JSON.
async function api(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(path);
  return res.json();
}

// Built an element with optional class and text without touching innerHTML.
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Drew a table from a header list and rows of plain strings.
function table(head, rows, emptyText) {
  if (!rows.length) return el('div', 'empty', emptyText);
  const [t, thead, tbody, tr] = ['table', 'thead', 'tbody', 'tr'].map((tag) => el(tag));
  head.forEach((h) => tr.append(el('th', '', h)));
  thead.append(tr);
  rows.forEach((r) => {
    const row = el('tr');
    r.forEach((cell) => row.append(cell instanceof Node ? cell : el('td', '', cell)));
    tbody.append(row);
  });
  t.append(thead, tbody);
  return t;
}

// Wrapped text in a table cell holding a small protocol badge.
function badge(text) {
  const td = el('td');
  td.append(el('span', 'tag', text));
  return td;
}

// Rendered the live translation rows in the same columns as the CLI show output.
function renderTranslations(rows) {
  const data = rows.map((r) => [badge(r.pro), r.inside_global, r.inside_local, r.outside_local, r.outside_global, `${r.ttl}s`, r.state]);
  $('translations').replaceChildren(table(COLS, data, 'No translations yet. Send traffic through in0 to see mappings appear.'));
}

// Rendered how many flows each pool address carried so far.
function renderPool(rows, cfg) {
  const counts = {};
  rows.forEach((r) => { const ip = r.inside_global.split(':')[0]; counts[ip] = (counts[ip] || 0) + 1; });
  const max = Math.max(1, ...Object.values(counts));
  const data = Object.entries(counts).map(([ip, n]) => {
    const [td, bar, fill] = [el('td'), el('div', 'bar'), el('i')];
    fill.style.width = `${(n / max) * 100}%`;
    bar.append(fill);
    td.append(bar);
    return [ip, String(n), td];
  });
  $('pool').replaceChildren(table(['Pool address', 'Flows', 'Share'], data, `Pool ${cfg.pool} (${cfg.pool_size} addresses) has no active flows.`));
}

// Listed every configured timeout so the behaviour behind the table stayed visible.
function renderTimeouts(cfg) {
  const data = Object.entries(cfg.timeouts).map(([k, v]) => [k, `${v}s`]);
  data.push(['mss clamp', cfg.mss ? String(cfg.mss) : 'off']);
  $('timeouts').replaceChildren(table(['Setting', 'Value'], data, ''));
}

// Updated the status pill to show whether the engine answered.
function setStatus(ok, text) {
  const pill = $('pill');
  pill.className = `pill ${ok ? 'ok' : 'off'}`;
  pill.querySelector('b').textContent = ok ? 'Translating' : 'Offline';
  $('status-text').textContent = text;
}

// Pulled every endpoint once and repainted the page from the results.
async function refresh() {
  try {
    const [rows, stats, cfg] = await Promise.all([api('/api/translations'), api('/api/stats'), api('/api/config')]);
    $('s-active').textContent = stats.active;
    $('s-out').textContent = stats.outbound;
    $('s-in').textContent = stats.inbound;
    $('s-drop').textContent = stats.dropped;
    renderTranslations(rows);
    renderPool(rows, cfg);
    renderTimeouts(cfg);
    setStatus(true, `Translating for ${cfg.pool} pool, ${rows.length} active`);
  } catch {
    setStatus(false, 'Lost contact with the engine, retrying');
  }
}

document.querySelectorAll('.tab').forEach((tab) =>
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('on', t === tab));
    ['translations', 'pool', 'timeouts'].forEach((id) => { $(id).hidden = id !== tab.dataset.tab; });
  }),
);

refresh();
setInterval(refresh, 1500);
