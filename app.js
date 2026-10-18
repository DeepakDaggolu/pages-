'use strict';
/* pages! — encrypted, offline, open-source Doc editor with lockable Vaults.
   Crypto: PBKDF2-SHA256 (600k iterations) -> AES-256-GCM via the browser's Web Crypto API.
   Main password protects everything. A Vault can also have its own password.
   No network calls, no analytics, no third-party code. */

const enc = new TextEncoder(), dec = new TextDecoder();
const $ = id => document.getElementById(id);
const META = 'vw_meta', DOC = 'vw_doc_', VLT = 'vw_vault_';
const IDLE_MS = 2 * 60 * 1000, HIDDEN_MS = 30 * 1000;

let key = null;                 // main key
let vaults = new Map();         // id -> {id,name,mode,protect,created,salt?,check?}
let vkeys = new Map();          // id -> key of unlocked own-password Vaults
let docs = new Map();           // id -> {id,vid,title,html,updated} (unlocked Vaults only)
let cur = null, openV = new Set();
let saveTimer = null, idleTimer = null, hiddenAt = 0, fails = 0;
const vfails = new Map();

/* ---------- helpers ---------- */
const toB64 = buf => {
  const a = new Uint8Array(buf); let s = '';
  for (let i = 0; i < a.length; i += 8192) s += String.fromCharCode(...a.subarray(i, i + 8192));
  return btoa(s);
};
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const getMeta = () => { try { return JSON.parse(localStorage.getItem(META)); } catch { return null; } };
const say = t => { $('status').textContent = t; };
const err = t => { $('err').textContent = t; };
const byUpdated = (a, b) => b.updated - a.updated;
const names = prefix => { const o = []; for (let i = 0; i < localStorage.length; i++) { const n = localStorage.key(i); if (n.startsWith(prefix)) o.push(n); } return o; };
const readEnv = n => { try { return JSON.parse(localStorage.getItem(n)); } catch { return null; } };
const vidOf = e => (e && e.vid) || 'general';          // older Docs had no Vault: they belong to "general"
const keyFor = vid => { const v = vaults.get(vid); return !v ? null : v.mode === 'own' ? (vkeys.get(vid) || null) : key; };
const isOpen = vid => !!keyFor(vid);

/* ---------- "stay unlocked": the main key is kept on this phone (non-extractable) ---------- */
const stayOn = () => localStorage.getItem('vw_stay') !== '0';
const idb = () => new Promise((res, rej) => { const r = indexedDB.open('pages_kv', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const idbDo = (mode, fn) => idb().then(db => new Promise((res, rej) => { const t = db.transaction('kv', mode), q = fn(t.objectStore('kv')); t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error); }));
const idbGet = k => idbDo('readonly', st => st.get(k));
const idbSet = (k, v) => idbDo('readwrite', st => st.put(v, k));
const idbDel = k => idbDo('readwrite', st => st.delete(k));
function updateStay() { $('stayBtn').textContent = stayOn() ? 'Stay unlocked: ON (tap to turn off)' : 'Stay unlocked: OFF (tap to turn on)'; }
async function toggleStay() {
  if (stayOn()) { localStorage.setItem('vw_stay', '0'); await idbDel('mainkey').catch(() => {}); say('Password will be needed every time.'); }
  else { localStorage.setItem('vw_stay', '1'); await idbSet('mainkey', key).catch(() => {}); say('pages! will stay unlocked on this phone until you tap Lock.'); }
  updateStay();
}

/* ---------- crypto ---------- */
async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encrypt(k, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify(obj)));
  return { iv: toB64(iv), ct: toB64(ct) };
}
async function decrypt(k, p) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(p.iv) }, k, fromB64(p.ct));
  return JSON.parse(dec.decode(pt));
}

/* ---------- sanitizer (allow-list) ---------- */
const TAGS = new Set(['P','BR','B','STRONG','I','EM','U','S','STRIKE','H1','H2','H3','UL','OL','LI','BLOCKQUOTE','A','DIV','SPAN','FONT','MARK','IMG']);
const FACES = new Set(['pg-serif','pg-sans','pg-mono','pg-hand']);
const ALIGNABLE = new Set(['P','DIV','H1','H2','H3','LI','BLOCKQUOTE']);
function sanitize(html) {
  const d = new DOMParser().parseFromString(String(html), 'text/html');
  const walk = node => {
    [...node.children].forEach(el => {
      if (!TAGS.has(el.tagName)) { el.replaceWith(...(['SCRIPT','STYLE','IFRAME','OBJECT','EMBED'].includes(el.tagName) ? [] : el.childNodes)); return; }
      [...el.attributes].forEach(a => {
        const t = el.tagName, n = a.name, v = a.value.trim();
        const ok = (t === 'A' && n === 'href' && /^(https?:|mailto:)/i.test(v))
          || (t === 'FONT' && ((n === 'face' && FACES.has(v)) || (n === 'size' && /^[1-7]$/.test(v)) || (n === 'color' && /^#[0-9a-f]{6}$/i.test(v))))
          || (t === 'IMG' && ((n === 'src' && /^data:image\/(png|jpeg|webp|gif);base64,/i.test(v)) || n === 'alt'))
          || (ALIGNABLE.has(t) && n === 'align' && /^(left|center|right|justify)$/.test(v));
        if (!ok) el.removeAttribute(n);
      });
      if (el.tagName === 'A') { el.setAttribute('rel', 'noopener noreferrer'); el.setAttribute('target', '_blank'); }
      walk(el);
    });
  };
  walk(d.body);
  return d.body.innerHTML;
}

/* ---------- dialog (replaces prompt/confirm so passwords stay hidden) ---------- */
function ask({ title, msg = '', fields = [], ok = 'OK', danger = false, validate }, preset = []) {
  return new Promise(resolve => {
    $('dlgTitle').textContent = title; $('dlgMsg').textContent = msg; $('dlgErr').textContent = '';
    const box = $('dlgFields'); box.replaceChildren();
    const els = fields.map(f => {
      let el;
      if (f.type === 'select') {
        el = document.createElement('select');
        f.options.forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; el.append(o); });
      } else {
        el = document.createElement('input'); el.type = f.type || 'text'; el.autocomplete = 'off'; el.maxLength = 120;
        if (f.value) el.value = f.value;
        el.addEventListener('keydown', e => { if (e.key === 'Enter') $('dlgOk').click(); });
      }
      if (preset[fields.indexOf(f)]) el.value = preset[fields.indexOf(f)];
      el.placeholder = f.placeholder || ''; el.setAttribute('aria-label', f.label || f.placeholder || 'Field');
      box.append(el); return el;
    });
    $('dlgOk').textContent = ok; $('dlgOk').className = danger ? 'danger' : 'primary';
    const done = v => { $('dlg').hidden = true; $('dlgOk').onclick = null; $('dlgCancel').onclick = null; resolve(v); };
    $('dlgOk').onclick = () => {
      const vals = els.map(e => e.value), m = validate && validate(vals);
      if (m) { $('dlgErr').textContent = m; return; }
      done(vals);
    };
    $('dlgCancel').onclick = () => done(null);
    $('dlg').hidden = false; (els[0] || $('dlgOk')).focus();
  });
}
const newPwFields = [
  { type: 'password', placeholder: 'Password', label: 'Password' },
  { type: 'password', placeholder: 'Repeat password', label: 'Repeat password' }
];
const checkNewPw = v => v[0].length < 10 ? 'Use at least 10 characters. A few random words work well.' : v[0] !== v[1] ? 'The two passwords do not match.' : '';

/* ---------- lock screen ---------- */
function showLock() {
  const first = !getMeta();
  $('pw2').hidden = !first;
  $('go').textContent = first ? 'Set password' : 'Unlock';
  $('lockHint').textContent = first
    ? 'Create a main password. It protects everything in pages! on this device and cannot be recovered if you forget it.'
    : 'Enter your main password to unlock pages!.';
  $('lock').hidden = false; $('app').hidden = true; err('');
}

async function submitLock() {
  err('');
  const pw = $('pw').value, meta = getMeta();
  try {
    if (!meta) {
      if (pw.length < 10) return err('Use at least 10 characters. A few random words work well.');
      if (pw !== $('pw2').value) return err('The two passwords do not match.');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const k = await deriveKey(pw, salt);
      localStorage.setItem(META, JSON.stringify({ v: 1, salt: toB64(salt), check: await encrypt(k, { ok: 1 }) }));
      key = k;
    } else {
      if (fails) await new Promise(r => setTimeout(r, Math.min(fails * 1000, 8000)));
      const k = await deriveKey(pw, fromB64(meta.salt));
      try { await decrypt(k, meta.check); } catch { fails++; return err('Wrong password.'); }
      key = k; fails = 0;
    }
    $('pw').value = ''; $('pw2').value = '';
    if (stayOn()) idbSet('mainkey', key).catch(() => {});
    await openApp();
  } catch (e) { err('Something went wrong. Reload the page and try again.'); }
}

/* ---------- storage ---------- */
async function saveVault(v) { localStorage.setItem(VLT + v.id, JSON.stringify(await encrypt(key, v))); }

async function loadVaults() {
  vaults.clear();
  for (const n of names(VLT)) {
    try { const v = await decrypt(key, readEnv(n)); vaults.set(v.id, v); } catch {}
  }
  if (!vaults.size) {
    const v = { id: 'general', name: 'My Vault', mode: 'main', protect: false, created: Date.now() };
    vaults.set(v.id, v); await saveVault(v);
  }
}

async function loadDocs() {
  docs.clear();
  for (const n of names(DOC)) {
    const e = readEnv(n); if (!e) continue;
    const vid = vidOf(e), k = keyFor(vid); if (!k) continue;
    try { const d = await decrypt(k, e); d.vid = vid; docs.set(d.id, d); } catch {}
  }
}

async function persist(d) {
  const k = keyFor(d.vid);
  localStorage.setItem(DOC + d.id, JSON.stringify({ vid: d.vid, ...(await encrypt(k, d)) }));
}

/* ---------- app ---------- */
async function openApp() {
  await loadVaults(); await loadDocs();
  $('lock').hidden = true; $('app').hidden = false; updateStay();
  const first = [...docs.values()].sort(byUpdated)[0];
  if (first) openDoc(first.id);
  else {
    const v = [...vaults.values()].find(x => isOpen(x.id));
    if (v) await newDoc(v.id); else emptyState();
  }
  resetIdle();
}

function setEnabled(on) { $('editor').setAttribute('contenteditable', on ? 'true' : 'false'); $('title').disabled = !on; }

function emptyState() {
  cur = null; $('editor').replaceChildren(); $('title').value = ''; setEnabled(false);
  say('Open the Vaults menu to unlock a Vault.');
}

const SIZES = [['letter', 'Letter (8.5 × 11 in)'], ['legal', 'Legal (8.5 × 14 in)'], ['a4', 'A4'], ['a5', 'A5'], ['postcard', 'Postcard (4 × 6 in)']];
const DEFAULT_LAYOUT = { s: 'letter', o: 'portrait' };
function fit() {   // shrink the page to fit narrow phone screens
  const e = $('editor'); e.style.zoom = 1;
  e.style.zoom = Math.min(1, ($('scroller').clientWidth - 20) / e.offsetWidth);
}
function applyLayout(d) {
  const l = d.layout || DEFAULT_LAYOUT;
  $('editor').className = 'page s-' + l.s + ' o-' + l.o; fit();
}
async function pickLayout(l) {
  l = l || DEFAULT_LAYOUT;
  const r = await ask({
    title: 'Page layout', msg: 'Choose the page size and direction for this Doc.',
    fields: [{ type: 'select', label: 'Page size', options: SIZES }, { type: 'select', label: 'Direction', options: [['portrait', 'Portrait'], ['landscape', 'Landscape']] }], ok: 'Apply'
  }, [l.s, l.o]);
  return r && { s: r[0], o: r[1] };
}

async function newDoc(vid, chooseLayout) {
  vid = vid || (cur && docs.get(cur) && docs.get(cur).vid) || [...vaults.keys()].find(isOpen);
  if (!vid || !isOpen(vid)) { say('Unlock a Vault first.'); return; }
  let layout = DEFAULT_LAYOUT;
  if (chooseLayout) { layout = await pickLayout(); if (!layout) return; }
  await saveNow();
  const d = { id: crypto.randomUUID(), vid, title: '', html: '', layout, updated: Date.now() };
  docs.set(d.id, d); await persist(d); openV.add(vid); openDoc(d.id); closeDrawer(); $('editor').focus();
}

function openDoc(id) {
  const d = docs.get(id); if (!d) return;
  cur = id; setEnabled(true);
  $('title').value = d.title; $('editor').innerHTML = sanitize(d.html); applyLayout(d);
  say('Encrypted and saved on this device');
}

async function saveNow() {
  clearTimeout(saveTimer);
  if (!key || !cur || !docs.has(cur)) return;
  const d = docs.get(cur);
  d.title = $('title').value.trim(); d.html = $('editor').innerHTML; d.updated = Date.now();
  try { await persist(d); say('Encrypted and saved on this device'); }
  catch { say('Could not save. Device storage may be full.'); }
}
const queueSave = () => { say('Saving…'); clearTimeout(saveTimer); saveTimer = setTimeout(saveNow, 700); };

async function deleteDoc() {
  if (!cur || !docs.has(cur)) return;
  const d = docs.get(cur);
  const r = await ask({ title: 'Delete this Doc?', msg: '“' + (d.title || 'Untitled') + '” will be deleted permanently.', ok: 'Delete', danger: true });
  if (!r) return;
  clearTimeout(saveTimer);
  localStorage.removeItem(DOC + cur); docs.delete(cur); cur = null;
  const same = [...docs.values()].filter(x => x.vid === d.vid).sort(byUpdated)[0];
  if (same) openDoc(same.id); else await newDoc(d.vid);
  closeDrawer();
}

/* ---------- Vaults ---------- */
function chip(t) { const s = document.createElement('span'); s.className = 'chip'; s.textContent = t; return s; }
function btn(text, fn, cls) { const b = document.createElement('button'); b.type = 'button'; b.textContent = text; if (cls) b.className = cls; b.onclick = fn; return b; }

function renderList() {
  const root = $('vaults'); root.replaceChildren();
  [...vaults.values()].sort((a, b) => a.created - b.created).forEach(v => {
    const open = isOpen(v.id), expanded = open && openV.has(v.id);
    const sec = document.createElement('section'); sec.className = 'vault';
    const head = btn('', () => toggleVault(v.id), 'vhead');
    const nm = document.createElement('span'); nm.className = 'vname'; nm.textContent = v.name; head.append(nm);
    if (v.mode === 'own') head.append(chip(open ? 'Open' : 'Locked'));
    if (v.protect) head.append(chip('Protected'));
    head.setAttribute('aria-expanded', String(expanded));
    sec.append(head);
    if (expanded) {
      const mine = [...docs.values()].filter(d => d.vid === v.id).sort(byUpdated);
      if (mine.length) {
        const ul = document.createElement('ul');
        mine.forEach(d => {
          const li = document.createElement('li'), b = btn(d.title || 'Untitled', async () => { await saveNow(); openDoc(d.id); closeDrawer(); });
          if (d.id === cur) b.setAttribute('aria-current', 'true');
          li.append(b); ul.append(li);
        });
        sec.append(ul);
      } else { const p = document.createElement('p'); p.className = 'empty'; p.textContent = 'No Docs yet.'; sec.append(p); }
      const acts = document.createElement('div'); acts.className = 'acts';
      acts.append(btn('New Doc', () => newDoc(v.id, true)), btn('Rename', () => renameVault(v.id)),
        btn(v.protect ? 'Unprotect' : 'Protect', () => toggleProtect(v.id)));
      if (v.mode === 'own') acts.append(btn('Lock now', () => lockVault(v.id)));
      acts.append(btn('Delete Vault', () => deleteVault(v.id)));
      sec.append(acts);
    }
    root.append(sec);
  });
}

async function toggleVault(vid) {
  if (!isOpen(vid)) await unlockVault(vid);
  else if (openV.has(vid)) openV.delete(vid); else openV.add(vid);
  renderList();
}

async function createVault() {
  const r = await ask({
    title: 'New Vault', msg: 'A Vault is a folder for your Docs.',
    fields: [
      { placeholder: 'Vault name', label: 'Vault name' },
      { type: 'select', label: 'Protection', options: [['main', 'Use my main password'], ['own', 'Give it its own password']] }
    ],
    ok: 'Continue', validate: v => v[0].trim() ? '' : 'Enter a name.'
  });
  if (!r) return;
  const v = { id: crypto.randomUUID(), name: r[0].trim(), mode: r[1], protect: false, created: Date.now() };
  if (v.mode === 'own') {
    const p = await ask({
      title: 'Vault password', msg: 'Only this password opens “' + v.name + '”. If you forget it, the Docs inside cannot be recovered.',
      fields: newPwFields, ok: 'Create Vault', validate: checkNewPw
    });
    if (!p) return;
    say('Creating Vault…');
    const salt = crypto.getRandomValues(new Uint8Array(16)), vk = await deriveKey(p[0], salt);
    v.salt = toB64(salt); v.check = await encrypt(vk, { ok: 1 }); vkeys.set(v.id, vk);
  }
  vaults.set(v.id, v); await saveVault(v); openV.add(v.id); renderList(); say('Vault created.');
}

async function unlockVault(vid) {
  const v = vaults.get(vid); if (!v || v.mode !== 'own') return;
  const r = await ask({
    title: 'Unlock “' + v.name + '”', msg: 'Enter this Vault’s own password.',
    fields: [{ type: 'password', placeholder: 'Vault password', label: 'Vault password' }], ok: 'Unlock'
  });
  if (!r) return;
  const n = vfails.get(vid) || 0;
  if (n) await new Promise(res => setTimeout(res, Math.min(n * 1000, 8000)));
  say('Unlocking…');
  try {
    const k = await deriveKey(r[0], fromB64(v.salt));
    await decrypt(k, v.check);
    vkeys.set(vid, k); vfails.delete(vid);
    await saveNow(); await loadDocs(); openV.add(vid);
    if (!cur) {
      const f = [...docs.values()].filter(d => d.vid === vid).sort(byUpdated)[0];
      if (f) openDoc(f.id); else await newDoc(vid);
    }
    say('Vault unlocked.');
  } catch { vfails.set(vid, n + 1); say('Wrong Vault password.'); }
}

async function lockVault(vid) {
  const c = cur && docs.get(cur);
  if (c && c.vid === vid) { await saveNow(); cur = null; $('editor').replaceChildren(); $('title').value = ''; }
  vkeys.delete(vid); openV.delete(vid);
  for (const [id, d] of docs) if (d.vid === vid) docs.delete(id);
  if (!cur) { const f = [...docs.values()].sort(byUpdated)[0]; if (f) openDoc(f.id); else emptyState(); }
  renderList(); say('Vault locked.');
}

async function renameVault(vid) {
  const v = vaults.get(vid);
  const r = await ask({
    title: 'Rename Vault', fields: [{ placeholder: 'Vault name', label: 'Vault name', value: v.name }],
    ok: 'Save', validate: x => x[0].trim() ? '' : 'Enter a name.'
  });
  if (!r) return;
  v.name = r[0].trim(); await saveVault(v); renderList();
}

async function toggleProtect(vid) {
  const v = vaults.get(vid); v.protect = !v.protect; await saveVault(v); renderList();
  say(v.protect ? 'Protected: skipped by Delete everything.' : 'No longer protected.');
}

async function wipeVaults(ids) {
  clearTimeout(saveTimer);
  for (const n of names(DOC)) { const e = readEnv(n); if (e && ids.includes(vidOf(e))) localStorage.removeItem(n); }
  ids.forEach(id => { localStorage.removeItem(VLT + id); vaults.delete(id); vkeys.delete(id); openV.delete(id); });
  for (const [id, d] of docs) if (ids.includes(d.vid)) docs.delete(id);
  if (cur && !docs.has(cur)) { cur = null; $('editor').replaceChildren(); $('title').value = ''; }
  if (!vaults.size) {
    const v = { id: 'general', name: 'My Vault', mode: 'main', protect: false, created: Date.now() };
    vaults.set(v.id, v); await saveVault(v);
  }
  if (!cur) {
    const f = [...docs.values()].sort(byUpdated)[0];
    if (f) openDoc(f.id);
    else { const v = [...vaults.values()].find(x => isOpen(x.id)); if (v) await newDoc(v.id); else emptyState(); }
  }
  renderList();
}

async function deleteVault(vid) {
  const v = vaults.get(vid);
  const r = await ask({
    title: 'Delete “' + v.name + '”?',
    msg: v.protect ? 'This Vault is protected. Delete it and every Doc inside it forever?' : 'Delete this Vault and every Doc inside it forever?',
    ok: 'Delete', danger: true
  });
  if (r) await wipeVaults([vid]);
}

async function deleteEverything() {
  const ids = [...vaults.values()].filter(v => !v.protect).map(v => v.id);
  const kept = vaults.size - ids.length;
  const r = await ask({
    title: 'Delete everything?',
    msg: 'Deletes every Vault that is not Protected, with all Docs inside. Protected Vaults are kept. This cannot be undone.',
    ok: 'Delete everything', danger: true
  });
  if (!r) return;
  await wipeVaults(ids);
  say('Deleted. ' + kept + ' protected Vault' + (kept === 1 ? '' : 's') + ' kept.');
}

/* ---------- save a Doc to the phone as a file ---------- */
const esc = t => String(t).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const FILE_CSS = 'body{max-width:720px;margin:2rem auto;padding:0 1rem;font:18px/1.6 Georgia,serif;color:#111}'
  + 'font[face=pg-sans]{font-family:system-ui,Arial,sans-serif}font[face=pg-mono]{font-family:Menlo,Consolas,monospace}'
  + 'font[face=pg-hand]{font-family:"Comic Sans MS","Marker Felt",cursive}'
  + 'font[size="1"]{font-size:.7em}font[size="2"]{font-size:.85em}font[size="4"]{font-size:1.15em}font[size="5"]{font-size:1.5em}'
  + 'font[size="6"]{font-size:2em}font[size="7"]{font-size:2.6em}mark{background:#ffe066}'
  + 'blockquote{margin:1em 0;padding-left:14px;border-left:3px solid #999;color:#555}'
  + 'img{max-width:100%;height:auto}[align=center]{text-align:center}[align=right]{text-align:right}[align=justify]{text-align:justify}';

function download(name, type, text) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function saveToPhone() {
  if (!cur || !docs.has(cur)) { say('Open a Doc first.'); return; }
  await saveNow();
  const d = docs.get(cur);
  const r = await ask({
    title: 'Save to phone', msg: 'The saved file is NOT encrypted. Anyone who gets the file can read it.',
    fields: [{ type: 'select', label: 'Format', options: [['txt', 'Plain text (.txt)'], ['html', 'Web page (.html)']] }], ok: 'Save'
  });
  if (!r) return;
  const title = d.title || 'Untitled';
  const base = title.replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'doc';
  if (r[0] === 'txt') download(base + '.txt', 'text/plain', title + '\n\n' + $('editor').innerText);
  else download(base + '.html', 'text/html',
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'
    + esc(title) + '</title><style>' + FILE_CSS + '</style></head><body><h1>' + esc(title) + '</h1>' + sanitize($('editor').innerHTML) + '</body></html>');
  closeDrawer(); say('Saved to your downloads.');
}

/* ---------- lock everything ---------- */
function reset() {
  clearTimeout(saveTimer); clearTimeout(idleTimer);
  key = null; vkeys.clear(); vaults.clear(); docs.clear(); openV.clear(); cur = null;
  $('editor').replaceChildren(); $('title').value = ''; $('vaults').replaceChildren();
  $('dlg').hidden = true; closeDrawer();
}
async function lock() { await saveNow(); idbDel('mainkey').catch(() => {}); reset(); showLock(); }

/* ---------- backup ---------- */
function exportBackup() {
  const grab = p => names(p).map(n => ({ n, p: readEnv(n) }));
  const payload = { app: 'pages_app', v: 2, meta: getMeta(), vaults: grab(VLT), docs: grab(DOC) };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = 'pages-backup.json';
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function importBackup(file) {
  try {
    const data = JSON.parse(await file.text());
    if (!['pages_app', 'vault_pages', 'vaultwrite'].includes(data.app) || !data.meta || !Array.isArray(data.docs)) throw 0;
    const r = await ask({ title: 'Restore backup?', msg: 'This replaces everything on this device with the backup.', ok: 'Restore', danger: true });
    if (!r) return;
    await saveNow(); clearTimeout(saveTimer);
    [...names(DOC), ...names(VLT)].forEach(n => localStorage.removeItem(n));
    localStorage.setItem(META, JSON.stringify(data.meta));
    (data.vaults || []).forEach(x => { if (/^vw_vault_[\w-]+$/.test(x.n)) localStorage.setItem(x.n, JSON.stringify(x.p)); });
    data.docs.forEach(x => { if (/^vw_doc_[\w-]+$/.test(x.n)) localStorage.setItem(x.n, JSON.stringify(x.p)); });
    idbDel('mainkey').catch(() => {}); reset(); showLock();
    err('Backup restored. Unlock with the backup’s main password.');
  } catch { say('That file is not a valid pages! backup.'); }
}

/* ---------- auto-lock ---------- */
async function lockOwn() { await saveNow(); for (const id of [...vkeys.keys()]) await lockVault(id); }
const autoLock = () => stayOn() ? lockOwn() : lock();
function resetIdle() { clearTimeout(idleTimer); if (key) idleTimer = setTimeout(autoLock, IDLE_MS); }
['pointerdown', 'keydown', 'input', 'scroll'].forEach(t => addEventListener(t, resetIdle, { passive: true }));
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now();
  else if (key && Date.now() - hiddenAt > HIDDEN_MS) autoLock();
});

/* ---------- UI wiring ---------- */
const openDrawer = () => { renderList(); $('drawer').hidden = false; };
const closeDrawer = () => { $('drawer').hidden = true; };

$('go').onclick = submitLock;
$('pw').addEventListener('keydown', e => { if (e.key === 'Enter' && $('pw2').hidden) submitLock(); });
$('pw2').addEventListener('keydown', e => { if (e.key === 'Enter') submitLock(); });
$('lockBtn').onclick = lock;
$('menu').onclick = openDrawer;
$('closeDrawer').onclick = closeDrawer;
$('newVault').onclick = createVault;
$('stayBtn').onclick = toggleStay;
$('saveFile').onclick = saveToPhone;
$('del').onclick = deleteDoc;
$('delAll').onclick = deleteEverything;
$('exp').onclick = exportBackup;
$('impBtn').onclick = () => $('imp').click();
$('imp').onchange = e => { if (e.target.files[0]) importBackup(e.target.files[0]); e.target.value = ''; };
$('title').addEventListener('input', queueSave);
$('editor').addEventListener('input', queueSave);
$('print').onclick = () => print();
$('layout').onclick = async () => {
  if (!cur || !docs.has(cur)) return;
  const d = docs.get(cur), l = await pickLayout(d.layout);
  if (l) { d.layout = l; applyLayout(d); queueSave(); }
};
addEventListener('resize', fit);

// Remember the selection so toolbar menus (font, size, color) still apply to it.
let lastRange = null;
document.addEventListener('selectionchange', () => {
  const s = getSelection();
  if (s.rangeCount) { const r = s.getRangeAt(0); if ($('editor').contains(r.commonAncestorContainer)) lastRange = r.cloneRange(); }
});
const editable = () => $('editor').getAttribute('contenteditable') === 'true';
function restoreSel() {
  $('editor').focus();
  if (lastRange) { const s = getSelection(); s.removeAllRanges(); s.addRange(lastRange); }
}

// Keep the editor focused while using the toolbar buttons (menus need their normal behavior).
document.querySelector('.tools').addEventListener('mousedown', e => { if (e.target.tagName !== 'SELECT') e.preventDefault(); });

function clearColor() {
  const s = getSelection();
  $('editor').querySelectorAll('font[color]').forEach(f => { if (s.containsNode(f, true)) f.removeAttribute('color'); });
}
function onMenu(id, fn) {
  $(id).addEventListener('change', e => {
    const v = e.target.value; e.target.value = '';
    if (!v || !editable()) return;
    restoreSel(); document.execCommand('styleWithCSS', false, false); fn(v); queueSave();
  });
}
onMenu('fontFace', v => document.execCommand('fontName', false, v));
onMenu('fontSize', v => document.execCommand('fontSize', false, v));
onMenu('fontColor', v => v === 'none' ? clearColor() : document.execCommand('foreColor', false, v));

$('hl').onclick = () => {
  if (!editable()) return;
  restoreSel();
  const s = getSelection(); if (!s.rangeCount) return;
  const r = s.getRangeAt(0); if (!$('editor').contains(r.commonAncestorContainer)) return;
  const node = r.startContainer.nodeType === 1 ? r.startContainer : r.startContainer.parentElement;
  const m = node && node.closest('mark');
  if (m && $('editor').contains(m)) m.replaceWith(...m.childNodes);          // tap again to remove
  else if (!r.collapsed) { const mk = document.createElement('mark'); mk.appendChild(r.extractContents()); r.insertNode(mk); }
  else return;
  queueSave();
};
document.querySelectorAll('[data-cmd]').forEach(b => b.onclick = () => {
  $('editor').focus(); document.execCommand('styleWithCSS', false, false);
  document.execCommand(b.dataset.cmd, false, null); queueSave();
});
document.querySelectorAll('[data-block]').forEach(b => b.onclick = () => {
  $('editor').focus(); document.execCommand('formatBlock', false, b.dataset.block); queueSave();
});
$('link').onclick = async () => {
  const sel = getSelection(), rng = sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null;  // keep the selection while the dialog is open
  const r = await ask({ title: 'Add link', fields: [{ placeholder: 'https://…', label: 'Link address' }], ok: 'Add',
    validate: v => /^(https?:|mailto:)/i.test(v[0].trim()) ? '' : 'Only https, http, and mailto links are allowed.' });
  if (r) { $('editor').focus(); if (rng) { sel.removeAllRanges(); sel.addRange(rng); } document.execCommand('createLink', false, r[0].trim()); queueSave(); }
};

// Paste: images (screenshots) are shrunk and inserted; everything else is pasted as plain text.
function imgToData(file) {
  return new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onerror = rej;
    fr.onload = () => {
      const im = new Image();
      im.onerror = rej;
      im.onload = () => {
        const k = Math.min(1, 1000 / im.width), c = document.createElement('canvas');
        c.width = Math.round(im.width * k); c.height = Math.round(im.height * k);
        const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height); x.drawImage(im, 0, 0, c.width, c.height);
        res(c.toDataURL('image/jpeg', 0.82));
      };
      im.src = fr.result;
    };
    fr.readAsDataURL(file);
  });
}
async function insertImage(file) {
  try { document.execCommand('insertImage', false, await imgToData(file)); queueSave(); }
  catch { say('Could not add that image.'); }
}
$('editor').addEventListener('paste', e => {
  e.preventDefault();
  const cd = e.clipboardData || window.clipboardData;
  const img = [...(cd.files || [])].find(f => /^image\//.test(f.type));
  if (img) insertImage(img); else document.execCommand('insertText', false, cd.getData('text/plain'));
});
$('imgBtn').onclick = () => { if (editable()) $('imgIn').click(); };
$('imgIn').onchange = e => { const f = e.target.files[0]; e.target.value = ''; if (f) { restoreSel(); insertImage(f); } };

/* ---------- open files from the phone (.docx, .txt, .md, .html) ---------- */
async function readDocx(buf) {   // minimal zip reader: returns the text of word/document.xml
  const dv = new DataView(buf), u8 = new Uint8Array(buf);
  let e = buf.byteLength - 22; while (e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--;
  if (e < 0) throw 0;
  let p = dv.getUint32(e + 16, true);
  for (let i = 0, n = dv.getUint16(e + 10, true); i < n; i++) {
    const method = dv.getUint16(p + 10, true), size = dv.getUint32(p + 20, true), nl = dv.getUint16(p + 28, true);
    const xl = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), off = dv.getUint32(p + 42, true);
    const name = dec.decode(u8.subarray(p + 46, p + 46 + nl)); p += 46 + nl + xl + cl;
    if (name !== 'word/document.xml') continue;
    const start = off + 30 + dv.getUint16(off + 26, true) + dv.getUint16(off + 28, true), data = u8.subarray(start, start + size);
    if (method === 0) return dec.decode(data);
    return dec.decode(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer());
  }
  throw 0;
}
function docxToHtml(xml) {
  const d = new DOMParser().parseFromString(xml, 'application/xml'); let out = '';
  for (const p of d.getElementsByTagName('w:p')) {
    const st = p.getElementsByTagName('w:pStyle')[0], sv = (st && st.getAttribute('w:val')) || '';
    const tag = /^(Title|Heading1)$/i.test(sv) ? 'h1' : /^Heading[2-9]$/i.test(sv) ? 'h2' : 'p';
    const jc = p.getElementsByTagName('w:jc')[0], al = jc && jc.getAttribute('w:val');
    let h = p.getElementsByTagName('w:numPr')[0] ? '• ' : '';
    for (const r of p.getElementsByTagName('w:r')) {
      let t = '';
      for (const c of r.childNodes) {
        if (c.nodeName === 'w:t') t += esc(c.textContent); else if (c.nodeName === 'w:tab') t += '&emsp;'; else if (c.nodeName === 'w:br') t += '<br>';
      }
      if (!t) continue;
      const on = n => { const x = r.getElementsByTagName(n)[0]; return x && !['0', 'false', 'none'].includes(x.getAttribute('w:val')); };
      if (on('w:b')) t = '<b>' + t + '</b>'; if (on('w:i')) t = '<i>' + t + '</i>'; if (on('w:u')) t = '<u>' + t + '</u>';
      h += t;
    }
    const a = al === 'center' || al === 'right' ? ' align="' + al + '"' : al === 'both' ? ' align="justify"' : '';
    out += '<' + tag + a + '>' + (h || '<br>') + '</' + tag + '>';
  }
  return out;
}
async function importFile(f) {
  const vid = (cur && docs.get(cur) && docs.get(cur).vid) || [...vaults.keys()].find(isOpen);
  if (!vid) { say('Unlock a Vault first.'); return; }
  const ext = (f.name.split('.').pop() || '').toLowerCase(); let html;
  try {
    if (ext === 'docx') html = docxToHtml(await readDocx(await f.arrayBuffer()));
    else if (ext === 'html' || ext === 'htm') html = await f.text();
    else html = (await f.text()).split(/\r?\n/).map(l => '<p>' + (esc(l) || '<br>') + '</p>').join('');
  } catch { say('Could not open that file. Supported: .docx, .txt, .md, .html (older .doc files are not).'); return; }
  await saveNow();
  const d = { id: crypto.randomUUID(), vid, title: f.name.replace(/\.[^.]+$/, '').slice(0, 120), html: sanitize(html), layout: DEFAULT_LAYOUT, updated: Date.now() };
  docs.set(d.id, d); await persist(d); openV.add(vid); openDoc(d.id); closeDrawer(); say('Opened “' + d.title + '”.');
}
$('openBtn').onclick = () => $('openFile').click();
$('openFile').onchange = e => { const f = e.target.files[0]; e.target.value = ''; if (f) importFile(f); };

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
(async () => {
  try {
    const meta = getMeta();
    if (meta && stayOn()) {
      const k = await idbGet('mainkey');
      if (k) { await decrypt(k, meta.check); key = k; await openApp(); return; }
    }
  } catch { idbDel('mainkey').catch(() => {}); }
  showLock();
})();
