'use strict';
(() => {
  const MAX_BYTES = 8 * 1024 * 1024;
  const MAX_ROWS = 100;
  const TIMEOUT_MS = 30000;
  const el = id => document.getElementById(id);
  let token = '';
  let connected = false;
  let generation = 0;
  const active = new Map();
  const detailIds = {findings: 'finding-detail', events: 'event-detail'};

  function status(kind, text, error = false) {
    const node = el(`${kind}-status`);
    node.textContent = text;
    node.classList.toggle('error', error);
  }
  function clear(kind) {
    el(`${kind}-results`).replaceChildren();
    el(detailIds[kind]).textContent = kind === 'findings' ? 'Select a finding.' : 'Select an event.';
  }
  function disconnect(message = 'Disconnected') {
    generation++;
    token = '';
    connected = false;
    el('api-token').value = '';
    for (const controller of active.values()) controller.abort();
    active.clear();
    el('disconnect-button').disabled = true;
    el('connection-status').textContent = message;
    for (const kind of ['findings', 'events']) {
      clear(kind);
      status(kind, 'Connect to load records.');
      el(`${kind}-form`).querySelector('button').disabled = false;
      el(`${kind}-cancel`).disabled = true;
    }
  }
  function localInput(date) {
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }
  const now = new Date();
  for (const kind of ['findings', 'events']) {
    // datetime-local uses minute precision; include the current minute rather
    // than silently omitting the most recent records from the default range.
    el(`${kind}-to`).value = localInput(new Date(now.getTime() + 60000));
    el(`${kind}-from`).value = localInput(new Date(now.getTime() - (kind === 'findings' ? 24 : 1) * 3600000));
  }
  for (const kind of ['findings', 'events']) {
    el(`${kind}-tab`).addEventListener('click', () => {
      for (const view of ['findings', 'events']) {
        el(`${view}-pane`).hidden = view !== kind;
        if (view === kind) el(`${view}-tab`).setAttribute('aria-current', 'page');
        else el(`${view}-tab`).removeAttribute('aria-current');
      }
    });
  }

  function params(kind) {
    const from = new Date(el(`${kind}-from`).value);
    const to = new Date(el(`${kind}-to`).value);
    const limit = Number(el(`${kind}-limit`).value);
    if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) throw new Error('Choose a valid time range: From must precede To.');
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ROWS) throw new Error('Result limit must be between 1 and 100.');
    const result = new URLSearchParams({from: from.toISOString(), to: to.toISOString(), limit: String(limit)});
    const fields = kind === 'findings' ? {severity: 'severity', rule: 'rule_id'} : {severity: 'severity', source: 'source_type', account: 'account', resource: 'resource_id', contains: 'contains'};
    for (const [field, name] of Object.entries(fields)) {
      const value = el(`${kind}-${field}`).value.trim();
      if (value) result.set(name, value);
    }
    if (kind === 'events') result.set('order', 'desc');
    return result;
  }

  async function readBounded(response, controller) {
    if (!response.body) throw new Error('The server returned no response body.');
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_BYTES) {
          controller.abort();
          throw new Error('Response exceeds the console limit. Narrow your search.');
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    } finally {
      reader.releaseLock();
    }
  }

  // Keep exact row slices for detail. JSON.parse/JSON.stringify would round large
  // integer attributes. Parsed objects below are used only for table labels.
  function rawRows(text, key) {
    const ws = pos => { while (/\s/.test(text[pos] || '') && pos < text.length) pos++; return pos; };
    function end(pos) {
      if (text[pos] === '"') {
        for (let i = pos + 1; i < text.length; i++) {
          if (text[i] === '\\') i++;
          else if (text[i] === '"') return i + 1;
        }
      } else if (text[pos] === '{' || text[pos] === '[') {
        let depth = 0;
        for (let i = pos; i < text.length; i++) {
          if (text[i] === '"') { i = end(i) - 1; continue; }
          if (text[i] === '{' || text[i] === '[') depth++;
          if (text[i] === '}' || text[i] === ']') { if (--depth === 0) return i + 1; }
        }
      } else {
        let i = pos;
        while (i < text.length && !/[\s,}\]]/.test(text[i])) i++;
        return i;
      }
      throw new Error('Invalid server response.');
    }
    let pos = ws(0);
    if (text[pos] !== '{') throw new Error('Invalid server response.');
    pos = ws(pos + 1);
    while (pos < text.length && text[pos] !== '}') {
      const keyEnd = end(pos);
      const name = JSON.parse(text.slice(pos, keyEnd));
      pos = ws(keyEnd);
      if (text[pos] !== ':') throw new Error('Invalid server response.');
      pos = ws(pos + 1);
      if (name === key) {
        if (text[pos] !== '[') throw new Error('Invalid server response.');
        const rows = [];
        pos = ws(pos + 1);
        while (text[pos] !== ']') {
          if (rows.length === MAX_ROWS || text[pos] !== '{') throw new Error('Response exceeds the result limit or has invalid records.');
          const finish = end(pos);
          rows.push(text.slice(pos, finish));
          pos = ws(finish);
          if (text[pos] === ',') pos = ws(pos + 1);
          else if (text[pos] !== ']') throw new Error('Invalid server response.');
        }
        return rows;
      }
      pos = ws(end(pos));
      if (text[pos] === ',') pos = ws(pos + 1);
      else if (text[pos] !== '}') throw new Error('Invalid server response.');
    }
    throw new Error('Invalid server response.');
  }

  function render(kind, rows) {
    const fragment = document.createDocumentFragment();
    rows.forEach((raw, index) => {
      const row = JSON.parse(raw);
      const tr = document.createElement('tr');
      const values = kind === 'findings' ? [row.severity, row.title, row.rule_id, row.created_at] : [row.severity, row.message || row.id, row.source?.type, [row.resource?.id, row.resource?.account_id].filter(Boolean).join(' / '), row.timestamp];
      values.forEach((value, column) => {
        const td = document.createElement('td');
        const text = document.createElement(column === 0 ? 'span' : 'div');
        text.textContent = typeof value === 'string' ? value : '—';
        if (column === 0) {
          text.classList.add('severity');
          if (['low', 'medium', 'high', 'critical', 'trace', 'debug', 'info', 'warn', 'error'].includes(value)) text.classList.add(value);
        }
        td.append(text);
        if (column === 1 && kind === 'findings') {
          const id = document.createElement('div');
          id.className = 'hint'; id.textContent = typeof row.id === 'string' ? row.id : '—';
          td.append(id);
        }
        tr.append(td);
      });
      const td = document.createElement('td');
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'select-row'; button.textContent = 'Inspect';
      button.setAttribute('aria-label', `Inspect ${kind === 'findings' ? 'finding' : 'event'} ${index + 1}`);
      button.addEventListener('click', () => { el(detailIds[kind]).textContent = raw; el(detailIds[kind]).focus(); });
      td.append(button); tr.append(td); fragment.append(tr);
    });
    el(`${kind}-results`).replaceChildren(fragment);
  }

  async function load(kind) {
    if (!connected) { status(kind, 'Connect before loading records.', true); return; }
    active.get(kind)?.abort();
    const controller = new AbortController();
    const requestGeneration = generation;
    active.set(kind, controller);
    const button = el(`${kind}-form`).querySelector('button');
    button.disabled = true;
    el(`${kind}-cancel`).disabled = false;
    clear(kind);
    status(kind, 'Loading…');
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, TIMEOUT_MS);
    try {
      const query = params(kind);
      const response = await fetch(`/v1/${kind === 'findings' ? 'findings' : 'events'}?${query}`, {headers: token ? {Authorization: `Bearer ${token}`} : {}, credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal});
      if (requestGeneration !== generation || active.get(kind) !== controller) return;
      if (controller.signal.aborted) throw new DOMException('Request cancelled.', 'AbortError');
      if (response.status === 401 || response.status === 403) { disconnect('Access denied. Reconnect with a valid token.'); return; }
      if (!response.ok) { await response.body?.cancel(); throw new Error(response.status === 429 ? 'The server is busy. Retry with a narrower search.' : `Search failed (${response.status}). Please retry.`); }
      const text = await readBounded(response, controller);
      if (requestGeneration !== generation || active.get(kind) !== controller) return;
      if (controller.signal.aborted) throw new DOMException('Request cancelled.', 'AbortError');
      const parsed = JSON.parse(text);
      if (parsed.schema_version !== 1 || !Array.isArray(parsed[kind]) || parsed[kind].length > MAX_ROWS) throw new Error('Unsupported response or result limit exceeded.');
      const rows = rawRows(text, kind);
      render(kind, rows);
      el('connection-status').textContent = 'Connected';
      status(kind, rows.length ? `${rows.length} records returned${rows.length === Number(el(`${kind}-limit`).value) ? ' · limit reached; narrow the interval to investigate further' : ''}.` : 'No records matched this search. Source coverage has not been assessed.');
    } catch (error) {
      if (requestGeneration !== generation || active.get(kind) !== controller) return;
      clear(kind);
      status(kind, timedOut ? 'Request timed out. Narrow your search and retry.' : error.name === 'AbortError' ? 'Request cancelled.' : error instanceof SyntaxError || error instanceof TypeError ? 'Unable to read the server response. Check your connection and retry.' : error.message, true);
    } finally {
      clearTimeout(timer);
      if (active.get(kind) === controller) { active.delete(kind); button.disabled = false; el(`${kind}-cancel`).disabled = true; }
    }
  }
  el('connection-form').addEventListener('submit', event => {
    event.preventDefault();
    const nextToken = el('api-token').value;
    disconnect();
    token = nextToken;
    connected = true;
    el('disconnect-button').disabled = false;
    el('connection-status').textContent = 'Connecting…';
    void load('findings');
  });
  el('disconnect-button').addEventListener('click', () => disconnect());
  for (const kind of ['findings', 'events']) el(`${kind}-form`).addEventListener('submit', event => { event.preventDefault(); void load(kind); });
  for (const kind of ['findings', 'events']) el(`${kind}-cancel`).addEventListener('click', () => active.get(kind)?.abort());
  window.addEventListener('pagehide', () => disconnect());
})();
