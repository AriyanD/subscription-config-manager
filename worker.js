/* ====================================================================
 *  Subscription Hub – Cloudflare Worker (service-worker syntax)
 *
 *  REQUIRED SETUP
 *   1. KV namespace bound to this Worker with the variable name:  STORE
 *   2. Set your dashboard password in DASHBOARD_PASSWORD below (min 10 characters).
 *      (Optional, safer: a Secret named ADMIN_PASSWORD overrides it.)
 *   3. Optional text variable: SUB_FETCH_UA  (User-Agent for remote fetches)
 *   4. Optional Cron Trigger (e.g. "0 * * * *") if you enable Daily/Weekly
 *      scheduled background sync in the dashboard UI.
 * ==================================================================== */

const DASHBOARD_PASSWORD = "CHANGE_ME_TO_YOUR_OWN_PASSWORD";
const PLACEHOLDER_PASSWORD = "CHANGE_ME_" + "TO_YOUR_OWN_PASSWORD";   // do not edit (used to detect the default)
const MIN_PASSWORD_LENGTH = 10;

// Default number of configs to take from each group per rotation round (editable in the UI)
const DEFAULT_ROTATION_CHUNK = 3;

// Default subscription name shown by apps (editable in the dashboard)
const DEFAULT_SUB_TITLE = 'Subscription Hub';

// Default scheduled auto-sync mode: 'off' | 'daily' | 'weekly'
const DEFAULT_AUTO_SYNC = 'off';

// Initial entries if the database has never been saved
const defaultGroups = {
  "Germany_Server": {
    mode: "configs",
    enabled: true,
    configs: [
      "example://sample-1@192.0.2.1:443"
    ],
    subUrls: [],
    cachedSubConfigs: [],
    lastSynced: 0
  }
};

/* ---------- Limits & security settings ---------- */
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;     // login lasts 7 days
const SESSION_COOKIE = '__Host-subhub_session';
const LOGIN_MAX_FAILURES = 5;                     // wrong passwords allowed ...
const LOGIN_WINDOW_SECONDS = 15 * 60;             // ... per 15 minutes per IP
const MAX_GROUPS = 100;
const MAX_ENTRIES_PER_GROUP = 5000;
const MAX_LINE_LENGTH = 8192;
const MAX_SUB_URLS_PER_GROUP = 20;
const MAX_GROUP_NAME_LENGTH = 60;
const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10000;
const MAX_REMOTE_BYTES = 3 * 1024 * 1024;

const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;

// Any "scheme://" at the start of a line begins a NEW entry
const SCHEME_LINE_RE = new RegExp('^[a-z][a-z0-9+.-]*://', 'i');

const FETCH_UA = (typeof SUB_FETCH_UA !== 'undefined' && SUB_FETCH_UA) ? String(SUB_FETCH_UA) : 'SubHub/1.0';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduledSync(false));
});

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function getPassword() {
  if (typeof ADMIN_PASSWORD !== 'undefined' && ADMIN_PASSWORD) return String(ADMIN_PASSWORD);
  return DASHBOARD_PASSWORD;
}

function isPasswordUsable(pw) {
  return pw !== PLACEHOLDER_PASSWORD && String(pw).length >= MIN_PASSWORD_LENGTH;
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(str) {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(str))));
}

async function hmacHex(keyString, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(keyString),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)));
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function getCookie(header, name) {
  const parts = String(header || '').split(';');
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    if (p.slice(0, idx).trim() === name) return p.slice(idx + 1).trim();
  }
  return '';
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return toHex(arr);
}

function makeNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

/* ---------- Signed, expiring session cookie (stateless) ---------- */

async function createSessionValue(password) {
  const exp = String(Date.now() + SESSION_TTL_SECONDS * 1000);
  const sig = await hmacHex('sub-hub-session:' + password, exp);
  return exp + '.' + sig;
}

async function verifySessionValue(value, password) {
  const v = String(value || '');
  const dot = v.indexOf('.');
  if (dot < 1) return false;
  const exp = v.slice(0, dot);
  const sig = v.slice(dot + 1);
  if (!/^\d{10,16}$/.test(exp) || Number(exp) < Date.now()) return false;
  const expected = await hmacHex('sub-hub-session:' + password, exp);
  return safeEqual(sig, expected);
}

function sessionCookie(value, maxAge) {
  return SESSION_COOKIE + '=' + value + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + maxAge;
}

/* ---------- Responses with hardened headers ---------- */

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'X-Robots-Tag': 'noindex, nofollow',
  'Cache-Control': 'no-store'
};

function jsonResponse(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'content-type': 'application/json; charset=utf-8' }, BASE_HEADERS, extraHeaders || {})
  });
}

function textResponse(text, status, extraHeaders) {
  return new Response(text, {
    status: status || 200,
    headers: Object.assign({ 'content-type': 'text/plain; charset=utf-8' }, BASE_HEADERS, extraHeaders || {})
  });
}

function htmlResponse(builder, status) {
  const nonce = makeNonce();
  const csp = [
    "default-src 'none'",
    "script-src 'nonce-" + nonce + "'",
    "style-src 'nonce-" + nonce + "'",
    "img-src data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; ');
  return new Response(builder(nonce), {
    status: status || 200,
    headers: Object.assign({ 'content-type': 'text/html; charset=utf-8', 'Content-Security-Policy': csp }, BASE_HEADERS)
  });
}

function isSameOrigin(request, url) {
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return false;
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin' && site !== 'none') return false;
  return true;
}

async function readJson(request) {
  const type = String(request.headers.get('content-type') || '').toLowerCase();
  if (type.indexOf('application/json') !== 0) throw new HttpError(415, 'Expected JSON');
  const len = parseInt(request.headers.get('content-length') || '0', 10);
  if (len > MAX_REQUEST_BYTES) throw new HttpError(413, 'Request is too large');
  const text = await request.text();
  if (text.length > MAX_REQUEST_BYTES) throw new HttpError(413, 'Request is too large');
  try { return JSON.parse(text); } catch (e) { throw new HttpError(400, 'Invalid JSON'); }
}

/* ------------------------------------------------------------------ */
/* Request handler                                                     */
/* ------------------------------------------------------------------ */

async function handleRequest(request, event) {
  try {
    return await route(request, event);
  } catch (e) {
    if (e instanceof HttpError) return jsonResponse({ success: false, error: e.message }, e.status);
    return textResponse('Something went wrong. Please try again.', 500);
  }
}

async function route(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const isSubPath = path === '/sub' || path.startsWith('/sub/') || path.startsWith('/sub-');

  // 1. Subscription endpoint (secret link token). Wrong or missing tokens always look like a 404.
  if (isSubPath || url.searchParams.has('raw')) {
    if (method !== 'GET' && method !== 'HEAD') return textResponse('404 Not Found', 404);
    const token = await envFetchOrCreateSubToken();
    if (token && isSubRequestAuthorized(url, token)) return buildSubscriptionResponse(url);
    if (isSubPath) return textResponse('404 Not Found', 404);
  }

  // 2. Dashboard access
  const password = getPassword();
  if (!isPasswordUsable(password)) {
    return htmlResponse(getSetupPageHTML, 503);
  }

  if (method === 'POST' && path === '/login') {
    if (!isSameOrigin(request, url)) throw new HttpError(403, 'Cross-site request blocked');
    return handleLogin(request, password);
  }

  const isLoggedIn = await verifySessionValue(getCookie(request.headers.get('Cookie'), SESSION_COOKIE), password);

  if (!isLoggedIn) {
    if (method === 'GET' || method === 'HEAD') return htmlResponse(getLoginPageHTML, 200);
    return jsonResponse({ success: false, error: 'Please sign in first.' }, 401);
  }

  // 3. Authenticated API
  if (method === 'POST') {
    if (!isSameOrigin(request, url)) throw new HttpError(403, 'Cross-site request blocked');

    if (path === '/logout') {
      return jsonResponse({ success: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
    }
    if (path === '/fetch-sub') return handleFetchSub(request);
    if (path === '/sync-all') return handleSyncAll();
    if (path === '/save') return handleSave(request);
    if (path === '/regenerate-token') {
      const newToken = generateToken();
      await STORE.put("sub_token", newToken);
      return jsonResponse({ success: true, subToken: newToken });
    }
    return jsonResponse({ success: false, error: 'Not found' }, 404);
  }

  // 4. Dashboard page
  if (path !== '/') return Response.redirect(url.origin + '/', 302);

  // Also opportunistically check if a scheduled daily/weekly sync is due
  if (event && typeof event.waitUntil === 'function') {
    event.waitUntil(handleScheduledSync(false));
  }

  const [serverGroups, rotationChunk, adminTitle, subToken, rev, autoSync, lastAutoSync] = await Promise.all([
    envFetchGroups(), envFetchRotationChunk(), envFetchSubTitle(), envFetchOrCreateSubToken(),
    envFetchRev(), envFetchAutoSync(), envFetchLastAutoSync()
  ]);
  return htmlResponse(nonce => getAdminPanelHTML(nonce, url.origin, serverGroups, rotationChunk, subToken, adminTitle, rev, autoSync, lastAutoSync), 200);
}

/* ---------- Login with brute-force protection ---------- */

async function handleLogin(request, password) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = 'rl:' + ip;
  let fails = 0;
  try { fails = parseInt(await STORE.get(rlKey), 10) || 0; } catch (e) {}

  if (fails >= LOGIN_MAX_FAILURES) {
    return jsonResponse(
      { success: false, error: 'Too many attempts. Please wait 15 minutes and try again.' },
      429, { 'Retry-After': String(LOGIN_WINDOW_SECONDS) }
    );
  }

  const data = await readJson(request);
  const supplied = typeof data.password === 'string' ? data.password : '';
  const ok = safeEqual(await sha256Hex(supplied), await sha256Hex(password));

  if (ok) {
    try { await STORE.delete(rlKey); } catch (e) {}
    return jsonResponse({ success: true }, 200, {
      'Set-Cookie': sessionCookie(await createSessionValue(password), SESSION_TTL_SECONDS)
    });
  }

  fails += 1;
  try { await STORE.put(rlKey, String(fails), { expirationTtl: LOGIN_WINDOW_SECONDS }); } catch (e) {}
  const left = Math.max(0, LOGIN_MAX_FAILURES - fails);
  return jsonResponse({
    success: false,
    error: left > 0
      ? 'Incorrect password. ' + left + (left === 1 ? ' attempt' : ' attempts') + ' left.'
      : 'Too many attempts. Please wait 15 minutes and try again.'
  }, 401);
}

/* ---------- Remote subscription preview & bulk sync ---------- */

async function handleFetchSub(request) {
  const body = await readJson(request);
  const rawUrls = Array.isArray(body.urls) ? body.urls : (typeof body.url === 'string' ? [body.url] : []);
  const validUrls = rawUrls.map(u => String(u || '').trim()).filter(u => isHttpUrl(u)).slice(0, MAX_SUB_URLS_PER_GROUP);
  if (validUrls.length === 0) {
    return jsonResponse({
      success: false,
      error: "Please enter at least one valid http:// or https:// subscription link.",
      configs: [], count: 0
    }, 400);
  }
  const result = await fetchAndDecodeSubUrls(validUrls);
  const now = Date.now();
  return jsonResponse({
    success: result.configs.length > 0 || result.errors.length === 0,
    configs: result.configs.slice(0, MAX_ENTRIES_PER_GROUP),
    count: result.configs.length,
    lastSynced: result.configs.length > 0 ? now : 0,
    errors: result.errors
  });
}

async function handleSyncAll() {
  const summary = await syncAllStoredSubGroups();
  const latestGroups = await envFetchGroups();
  const rev = await envFetchRev();
  return jsonResponse({
    success: true,
    syncedGroups: summary.syncedGroups,
    totalConfigs: summary.totalConfigs,
    errors: summary.errors,
    groups: latestGroups,
    rev: rev
  });
}

async function handleScheduledSync(forceRun) {
  try {
    const schedule = await envFetchAutoSync();
    if (!forceRun && schedule === 'off') return;
    const lastRun = await envFetchLastAutoSync();
    const now = Date.now();
    // Allow a small 30-minute buffer so daily/weekly crons don't skip due to slight drift
    const intervalMs = schedule === 'weekly' ? (WEEK_MS - 30 * 60 * 1000) : (DAY_MS - 30 * 60 * 1000);
    if (!forceRun && lastRun > 0 && (now - lastRun) < intervalMs) return;

    await syncAllStoredSubGroups();
    await STORE.put("last_auto_sync", String(now));
  } catch (e) {}
}

async function syncAllStoredSubGroups() {
  const groups = await envFetchGroups();
  const names = Object.keys(groups);
  const updates = {};
  const errors = [];
  let syncedGroups = 0;
  let totalConfigs = 0;

  await Promise.all(names.map(async (g) => {
    const entry = normalizeGroupEntry(groups[g]);
    if (entry.mode === 'sub' && entry.subUrls.length > 0) {
      const res = await fetchAndDecodeSubUrls(entry.subUrls);
      if (res.configs.length > 0) {
        const clipped = res.configs.slice(0, MAX_ENTRIES_PER_GROUP);
        updates[g] = {
          subUrls: entry.subUrls,
          configs: clipped,
          lastSynced: Date.now()
        };
        syncedGroups += 1;
        totalConfigs += clipped.length;
      }
      if (res.errors.length > 0) {
        res.errors.forEach(err => errors.push(g + ': ' + err));
      }
    }
  }));

  if (Object.keys(updates).length > 0) {
    try {
      const latest = await envFetchGroups();
      let changed = false;
      Object.keys(updates).forEach(g => {
        const cur = latest[g];
        if (cur && cur.mode === 'sub' && JSON.stringify(cur.subUrls) === JSON.stringify(updates[g].subUrls)) {
          cur.cachedSubConfigs = updates[g].configs;
          cur.lastSynced = updates[g].lastSynced;
          changed = true;
        }
      });
      if (changed) {
        await STORE.put("server_groups", JSON.stringify(latest));
        await STORE.put("data_rev", randomHex(6));
      }
    } catch (e) {}
  }

  return { syncedGroups, totalConfigs, errors };
}

/* ---------- Save (with conflict detection & cache preservation) ---------- */

async function handleSave(request) {
  const data = await readJson(request);
  if (!data || typeof data !== 'object') throw new HttpError(400, 'Invalid data');

  const currentRev = await envFetchRev();
  if (!data.force && String(data.rev || '') !== currentRev) {
    return jsonResponse({
      success: false, conflict: true,
      error: 'These settings were changed in another tab or device since you opened this page.'
    }, 409);
  }

  if (data.groups && typeof data.groups === 'object' && !Array.isArray(data.groups)) {
    const keys = Object.keys(data.groups);
    if (keys.length > MAX_GROUPS) throw new HttpError(400, 'Too many groups (max ' + MAX_GROUPS + ').');

    const existingGroups = await envFetchGroups();
    const normalizedGroups = {};
    const usedNames = {};
    const prepared = keys.map(k => {
      let name = safeGroupName(k);
      let unique = name, n = 2;
      while (usedNames[unique]) { unique = name + '_' + n; n++; }
      usedNames[unique] = true;
      const incoming = limitEntry(normalizeGroupEntry(data.groups[k]));
      const prev = existingGroups[unique] || existingGroups[k];
      // Preserve newer background cache if the group's URLs did not change
      if (
        prev &&
        incoming.mode === 'sub' &&
        prev.mode === 'sub' &&
        JSON.stringify(prev.subUrls) === JSON.stringify(incoming.subUrls) &&
        (prev.lastSynced || 0) > (incoming.lastSynced || 0)
      ) {
        incoming.cachedSubConfigs = limitEntry(prev).cachedSubConfigs;
        incoming.lastSynced = prev.lastSynced;
      }
      return { name: unique, entry: incoming };
    });

    await Promise.all(prepared.map(async (p) => {
      if (p.entry.mode === 'sub' && p.entry.subUrls.length > 0) {
        const res = await fetchAndDecodeSubUrls(p.entry.subUrls);
        if (res.configs.length > 0) {
          p.entry.cachedSubConfigs = res.configs.slice(0, MAX_ENTRIES_PER_GROUP);
          p.entry.lastSynced = Date.now();
        }
      }
    }));
    prepared.forEach(p => { normalizedGroups[p.name] = p.entry; });   // keeps the order from the UI
    await STORE.put("server_groups", JSON.stringify(normalizedGroups));
  }

  if (data.rotationChunk !== undefined) {
    const parsedChunk = Math.min(500, Math.max(1, parseInt(data.rotationChunk, 10) || DEFAULT_ROTATION_CHUNK));
    await STORE.put("rotation_chunk", String(parsedChunk));
  }
  if (typeof data.subTitle === 'string') {
    const cleanTitle = data.subTitle.trim().slice(0, 100) || DEFAULT_SUB_TITLE;
    await STORE.put("sub_title", cleanTitle);
  }
  if (typeof data.autoSync === 'string') {
    const cleanSync = (data.autoSync === 'daily' || data.autoSync === 'weekly') ? data.autoSync : 'off';
    await STORE.put("auto_sync_schedule", cleanSync);
  }

  const newRev = randomHex(6);
  await STORE.put("data_rev", newRev);
  const latestGroups = await envFetchGroups();
  return jsonResponse({ success: true, groups: latestGroups, rev: newRev });
}

function safeGroupName(raw) {
  let name = String(raw || '').split('').filter(c => c.charCodeAt(0) >= 32).join('').trim().slice(0, MAX_GROUP_NAME_LENGTH);
  if (!name) name = 'Group';
  if (name === '__proto__' || name === 'constructor' || name === 'prototype') name = '_' + name;
  return name;
}

function limitEntry(entry) {
  const clip = list => list.filter(l => l.length <= MAX_LINE_LENGTH).slice(0, MAX_ENTRIES_PER_GROUP);
  return {
    mode: entry.mode,
    enabled: entry.enabled !== false,
    configs: clip(entry.configs),
    subUrls: clip(entry.subUrls).slice(0, MAX_SUB_URLS_PER_GROUP),
    cachedSubConfigs: clip(entry.cachedSubConfigs),
    lastSynced: Number(entry.lastSynced) > 0 ? Number(entry.lastSynced) : 0
  };
}

/* ------------------------------------------------------------------ */
/* Subscription output (auto-syncs remote sub links on client update)  */
/* ------------------------------------------------------------------ */

function isSubRequestAuthorized(url, token) {
  let candidate = '';
  const m = url.pathname.match(/^\/sub[\/-]([^\/]+)\/?$/);
  if (m) candidate = m[1];
  else if (url.pathname === '/sub') candidate = url.searchParams.get('key') || '';
  const raw = url.searchParams.get('raw') || '';
  const a = candidate !== '' && safeEqual(candidate, token);
  const b = raw !== '' && safeEqual(raw, token);
  return a || b;
}

async function buildSubscriptionResponse(url) {
  const serverGroups = await envFetchGroups();
  let rotationChunk = await envFetchRotationChunk();
  const subTitle = await envFetchSubTitle();

  // Optional query override e.g. /sub/<token>?chunk=5
  if (url.searchParams.has('chunk')) {
    const qChunk = parseInt(url.searchParams.get('chunk'), 10);
    if (Number.isFinite(qChunk) && qChunk >= 1) rotationChunk = Math.min(500, qChunk);
  }

  const groupNames = Object.keys(serverGroups);
  const cleaned = {};
  const cacheUpdates = {};
  const now = Date.now();

  await Promise.all(groupNames.map(async (g) => {
    const entry = normalizeGroupEntry(serverGroups[g]);
    if (entry.enabled === false) {
      cleaned[g] = [];
      return;
    }
    if (entry.mode === 'sub') {
      if (entry.subUrls.length > 0) {
        // Every time a client app updates the subscription link, sync external subUrls live
        const fetchResult = await fetchAndDecodeSubUrls(entry.subUrls);
        if (fetchResult.configs.length > 0) {
          const clipped = fetchResult.configs.slice(0, MAX_ENTRIES_PER_GROUP);
          cleaned[g] = clipped;
          cacheUpdates[g] = {
            subUrls: entry.subUrls,
            configs: clipped,
            lastSynced: now
          };
        } else {
          // Fall back to cached configs if the remote server is temporarily unreachable
          cleaned[g] = entry.cachedSubConfigs.filter(c => typeof c === 'string' && c.trim() !== '');
        }
      } else {
        cleaned[g] = [];
      }
    } else {
      const resolvedDirect = [];
      for (const line of entry.configs) {
        const trimmed = String(line || '').trim();
        if (!trimmed) continue;
        if (isHttpUrl(trimmed)) {
          const subRes = await fetchAndDecodeSubUrls([trimmed]);
          subRes.configs.forEach(c => resolvedDirect.push(c));
        } else {
          resolvedDirect.push(trimmed);
        }
      }
      cleaned[g] = resolvedDirect;
    }
  }));

  // Persist freshly synced configs and timestamp to KV without overwriting concurrent admin edits
  if (Object.keys(cacheUpdates).length > 0) {
    try {
      const latest = await envFetchGroups();
      let changed = false;
      Object.keys(cacheUpdates).forEach(g => {
        const cur = latest[g];
        if (cur && cur.mode === 'sub' && JSON.stringify(cur.subUrls) === JSON.stringify(cacheUpdates[g].subUrls)) {
          cur.cachedSubConfigs = cacheUpdates[g].configs;
          cur.lastSynced = cacheUpdates[g].lastSynced;
          changed = true;
        }
      });
      if (changed) await STORE.put("server_groups", JSON.stringify(latest));
    } catch (e) {}
  }

  // Round-robin: rotationChunk configs from group 1, then group 2, ... then loop back
  const allConfigs = [];
  let offset = 0;
  while (true) {
    let addedAny = false;
    for (const group of groupNames) {
      const list = cleaned[group] || [];
      const slice = list.slice(offset, offset + rotationChunk);
      if (slice.length === 0) continue;
      addedAny = true;
      const cleanGroupName = group.replace(/_/g, ' ');
      slice.forEach(config => allConfigs.push(renameConfigWithIP(config, cleanGroupName)));
    }
    if (!addedAny) break;
    offset += rotationChunk;
  }

  const subscriptionContent = allConfigs.join('\n');
  // ?format=plain lets you inspect the unencoded output in a browser
  const outputBody = url.searchParams.get('format') === 'plain'
    ? subscriptionContent
    : btoa(unescape(encodeURIComponent(subscriptionContent)));

  return new Response(outputBody, {
    headers: Object.assign({}, BASE_HEADERS, {
      'content-type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Profile-Title': 'base64:' + btoa(unescape(encodeURIComponent(subTitle))),
      'Profile-Update-Interval': '12'
    })
  });
}

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

function isHttpUrl(str) {
  const s = String(str || '').trim().toLowerCase();
  return s.startsWith('https://') || s.startsWith('http://');
}

function getScheme(str) {
  const m = String(str || '').trim().match(/^([a-z][a-z0-9+.\-]*):\/\//i);
  return m ? m[1].toLowerCase() : '';
}

function isEntryLine(str) {
  const s = String(str || '').trim();
  return SCHEME_LINE_RE.test(s) && !isHttpUrl(s);
}

// A line starting with ANY "scheme://" is a new entry. Only scheme-less lines without
// whitespace are treated as wrapped continuations (common with long IPv6 URLs).
function splitNonEmptyLines(text) {
  const rawLines = String(text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const stitched = [];
  for (const line of rawLines) {
    if (SCHEME_LINE_RE.test(line)) {
      stitched.push(line);
    } else if (
      stitched.length > 0 &&
      !/\s/.test(line) &&
      !line.startsWith('//') &&
      !line.startsWith(';') &&
      !line.startsWith('#')
    ) {
      stitched[stitched.length - 1] += line;
    }
  }
  return stitched;
}

function safeBase64Decode(b64) {
  const compact = String(b64 || '').trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (compact.length % 4)) % 4;
  const padded = compact + '='.repeat(padLen);
  try {
    return decodeURIComponent(escape(atob(padded)));
  } catch (e) {
    return atob(padded);
  }
}

function decodeSubscriptionPayload(rawBody) {
  const trimmed = String(rawBody || '').trim();
  if (!trimmed) return [];

  const directLines = splitNonEmptyLines(trimmed).filter(l => isEntryLine(l));
  if (directLines.length > 0) return directLines;

  try {
    const decoded = safeBase64Decode(trimmed);
    const decodedLines = splitNonEmptyLines(decoded).filter(l => isEntryLine(l));
    if (decodedLines.length > 0) return decodedLines;
  } catch (e) {}

  return directLines;
}

// Refuse obviously internal targets (defence in depth – Workers cannot reach private networks anyway)
function isBlockedFetchUrl(u) {
  let parsed;
  try { parsed = new URL(u); } catch (e) { return true; }
  const h = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  const m4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m4) {
    const a = +m4[1], b = +m4[2];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (h.indexOf(':') !== -1) {
    if (h === '::1' || h === '::' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  }
  return false;
}

async function readTextCapped(res, maxBytes) {
  const len = parseInt(res.headers.get('content-length') || '0', 10);
  if (len > maxBytes) throw new Error('Response too large');
  if (!res.body) return await res.text();
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch (e) {}
      throw new Error('Response too large');
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let pos = 0;
  chunks.forEach(c => { merged.set(c, pos); pos += c.byteLength; });
  return new TextDecoder().decode(merged);
}

async function fetchAndDecodeSubUrls(urls) {
  const errors = [];
  const list = (urls || []).slice(0, MAX_SUB_URLS_PER_GROUP);
  const perUrlConfigs = await Promise.all(list.map(async (targetUrl) => {
    const cleanUrl = String(targetUrl || '').trim();
    if (!isHttpUrl(cleanUrl)) return [];
    if (isBlockedFetchUrl(cleanUrl)) {
      errors.push(cleanUrl + ': address not allowed');
      return [];
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(cleanUrl, {
        method: 'GET',
        headers: { 'User-Agent': FETCH_UA, 'Accept': '*/*' },
        signal: controller.signal
      });
      if (!res.ok) {
        errors.push(cleanUrl + ': HTTP ' + res.status);
        return [];
      }
      const text = await readTextCapped(res, MAX_REMOTE_BYTES);
      const decoded = decodeSubscriptionPayload(text);
      if (decoded.length === 0) {
        errors.push(cleanUrl + ': No valid configs found');
        return [];
      }
      return decoded;
    } catch (err) {
      errors.push(cleanUrl + ': ' + (err && err.name === 'AbortError' ? 'Timed out' : (err && err.message ? err.message : 'Fetch error')));
      return [];
    } finally {
      clearTimeout(timer);
    }
  }));
  const allConfigs = [];
  perUrlConfigs.forEach(l => l.forEach(c => allConfigs.push(c)));
  return { configs: allConfigs, errors };
}

function normalizeGroupEntry(rawEntry) {
  if (Array.isArray(rawEntry)) {
    const cleaned = splitNonEmptyLines(rawEntry.join('\n'));
    const subUrls = cleaned.filter(c => isHttpUrl(c));
    const configs = cleaned.filter(c => !isHttpUrl(c));
    const mode = (subUrls.length > 0 && configs.length === 0) ? 'sub' : 'configs';
    return { mode, enabled: true, configs, subUrls, cachedSubConfigs: [], lastSynced: 0 };
  }
  if (rawEntry && typeof rawEntry === 'object') {
    const mode = rawEntry.mode === 'sub' ? 'sub' : 'configs';
    const enabled = rawEntry.enabled !== false;
    const configs = Array.isArray(rawEntry.configs)
      ? splitNonEmptyLines(rawEntry.configs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    const subUrls = Array.isArray(rawEntry.subUrls)
      ? rawEntry.subUrls.map(c => String(c || '').trim()).filter(c => isHttpUrl(c))
      : [];
    const cachedSubConfigs = Array.isArray(rawEntry.cachedSubConfigs)
      ? splitNonEmptyLines(rawEntry.cachedSubConfigs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    const lastSynced = Number(rawEntry.lastSynced) > 0 ? Number(rawEntry.lastSynced) : 0;
    return { mode, enabled, configs, subUrls, cachedSubConfigs, lastSynced };
  }
  return { mode: 'configs', enabled: true, configs: [], subUrls: [], cachedSubConfigs: [], lastSynced: 0 };
}

function normalizeAllGroups(rawGroups) {
  const out = {};
  Object.keys(rawGroups || {}).forEach(k => { out[k] = normalizeGroupEntry(rawGroups[k]); });
  return out;
}

/* ---------- Storage helpers ---------- */

function generateToken() {
  return randomHex(16);   // 128-bit random link token
}

async function envFetchOrCreateSubToken() {
  try {
    const existing = await STORE.get("sub_token");
    // Short legacy 6-digit codes are still accepted so existing links keep working
    if (existing && /^[A-Za-z0-9]{6,64}$/.test(existing.trim())) return existing.trim();
    const generated = generateToken();
    await STORE.put("sub_token", generated);
    return generated;
  } catch (e) {
    return '';   // never fall back to a guessable hard-coded token
  }
}

async function envFetchGroups() {
  try {
    const kvData = await STORE.get("server_groups");
    if (kvData !== null && kvData !== undefined) {
      const parsed = JSON.parse(kvData);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return normalizeAllGroups(parsed);
    }
  } catch (e) {}
  return normalizeAllGroups(defaultGroups);   // only when nothing has ever been saved
}

async function envFetchSubTitle() {
  try {
    const t = await STORE.get("sub_title");
    if (t && t.trim()) return t.trim();
  } catch (e) {}
  return DEFAULT_SUB_TITLE;
}

async function envFetchRotationChunk() {
  try {
    const kvChunk = await STORE.get("rotation_chunk");
    if (kvChunk) {
      const n = parseInt(kvChunk, 10);
      if (Number.isFinite(n) && n >= 1) return n;
    }
  } catch (e) {}
  return DEFAULT_ROTATION_CHUNK;
}

async function envFetchAutoSync() {
  try {
    const s = await STORE.get("auto_sync_schedule");
    if (s === 'daily' || s === 'weekly' || s === 'off') return s;
  } catch (e) {}
  return DEFAULT_AUTO_SYNC;
}

async function envFetchLastAutoSync() {
  try {
    const n = parseInt(await STORE.get("last_auto_sync"), 10);
    return Number.isFinite(n) && n > 0 ? n : 0;
  } catch (e) {
    return 0;
  }
}

async function envFetchRev() {
  try { return (await STORE.get("data_rev")) || '0'; } catch (e) { return '0'; }
}

/* ------------------------------------------------------------------ */
/* Host / IPv6 handling                                                */
/* ------------------------------------------------------------------ */

function isValidIPv6(s) {
  if (!/^[0-9a-fA-F:]+$/.test(s) || s.indexOf(':::') !== -1) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const toGroups = h => (h === '' ? [] : h.split(':'));
  const all = halves.flatMap(toGroups);
  if (all.some(g => g.length < 1 || g.length > 4)) return false;
  return halves.length === 2 ? all.length <= 7 : all.length === 8;
}

// Splits "host:port" for IPv4, domains, bracketed IPv6 and UNBRACKETED IPv6.
function splitHostPort(hostPort) {
  const hp = String(hostPort || '').trim();

  const bracket = hp.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) return { host: bracket[1], port: bracket[2] || '' };

  const colonCount = (hp.match(/:/g) || []).length;
  if (colonCount <= 1) {
    const m = hp.match(/^([^:/?#]+)(?::(\d+))?$/);
    return m ? { host: m[1], port: m[2] || '' } : { host: hp, port: '' };
  }

  const idx = hp.lastIndexOf(':');
  const candidateHost = hp.slice(0, idx);
  const candidatePort = hp.slice(idx + 1);
  if (/^\d{1,5}$/.test(candidatePort) && Number(candidatePort) <= 65535 && isValidIPv6(candidateHost)) {
    return { host: candidateHost, port: candidatePort };
  }
  if (isValidIPv6(hp)) return { host: hp, port: '' };
  return { host: hp, port: '' };
}

// Scheme-agnostic: handles URL-style entries, encoded-JSON bodies and legacy encoded bodies.
function renameConfigWithIP(config, groupName) {
  try {
    const rawConfig = String(config || '').trim();
    const scheme = getScheme(rawConfig);
    if (!scheme || scheme === 'http' || scheme === 'https') return config;

    const tryDecode = (s) => {
      try { return safeBase64Decode(s); } catch (e) { return null; }
    };

    const hashIndex = rawConfig.indexOf('#');
    let basePart = hashIndex !== -1 ? rawConfig.substring(0, hashIndex) : rawConfig;
    let ipAddress = "Unknown_IP";

    const schemeEnd = basePart.indexOf('://') + 3;
    const body = basePart.slice(schemeEnd).trim();

    if (body && body.indexOf('@') === -1) {
      const decodedBody = tryDecode(body);
      let configObj = null;
      if (decodedBody !== null) {
        try { configObj = JSON.parse(decodedBody); } catch (e) { configObj = null; }
      }
      if (configObj && typeof configObj === 'object' && !Array.isArray(configObj)) {
        const rawHost = String(configObj.add || configObj.host || "Unknown_IP").trim();
        const host = rawHost.replace(/^\[|\]$/g, '');
        configObj.ps = `${groupName} - ${host}`;
        return `${scheme}://${btoa(unescape(encodeURIComponent(JSON.stringify(configObj))))}`;
      }
    }

    const qIndex = basePart.indexOf('?', schemeEnd);
    const pathIndex = basePart.indexOf('/', schemeEnd);
    let authorityEnd = basePart.length;
    if (qIndex !== -1 && qIndex < authorityEnd) authorityEnd = qIndex;
    if (pathIndex !== -1 && pathIndex < authorityEnd) authorityEnd = pathIndex;

    const authorityPart = basePart.slice(0, authorityEnd);
    const restPart = basePart.slice(authorityEnd);
    const atIndex = authorityPart.lastIndexOf('@');

    if (atIndex !== -1) {
      const prefix = authorityPart.slice(0, atIndex + 1);
      const hostPort = authorityPart.slice(atIndex + 1);
      const parsed = splitHostPort(hostPort);
      if (parsed.host) {
        ipAddress = parsed.host;
        const isV6 = parsed.host.indexOf(':') !== -1;
        const hostOut = isV6 ? `[${parsed.host}]` : parsed.host;
        basePart = `${prefix}${hostOut}${parsed.port ? ':' + parsed.port : ''}${restPart}`;
      }
    } else {
      const decodedAuthority = tryDecode(authorityPart.slice(schemeEnd));
      const atInDecoded = decodedAuthority !== null ? decodedAuthority.lastIndexOf('@') : -1;
      if (atInDecoded !== -1) {
        const parsed = splitHostPort(decodedAuthority.slice(atInDecoded + 1));
        if (parsed.host) ipAddress = parsed.host;
      }
    }

    return `${basePart}#${encodeURIComponent(`${groupName} - ${ipAddress}`)}`;
  } catch (err) {}
  return config;
}

/* ------------------------------------------------------------------ */
/* SHARED THEME                                                        */
/*  - Flat colours only (no gradients).                                */
/*  - Default light/dark follows the OS.                               */
/*  - Custom colours (background / groups / buttons) are chosen on the */
/*    dashboard, saved in this browser and applied on every page.      */
/* ------------------------------------------------------------------ */

// Runs inside the browser (inlined into each page's <head>), so keep it self-contained.
function themeBoot() {
  var root = document.documentElement;
  var VARS = ['--bg', '--group', '--accent', '--accent-hover', '--accent-ink', '--accent-soft', '--accent-text'];

  function rgb(h) {
    h = String(h || '').replace('#', '');
    if (h.length === 3) h = h.replace(/(.)/g, '$1$1');
    if (!/^[0-9a-f]{6}$/i.test(h)) return null;
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  }
  function lum(a) {
    var v = a.map(function (x) { x = x / 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
  }
  function hex(a) {
    return '#' + a.map(function (x) { return ('0' + Math.max(0, Math.min(255, Math.round(x))).toString(16)).slice(-2); }).join('');
  }
  function mix(a, b, t) { return a.map(function (x, i) { return x + (b[i] - x) * t; }); }

  window.subhubApplyColors = function (c) {
    if (!c) {
      VARS.forEach(function (n) { root.style.removeProperty(n); });
      root.removeAttribute('data-theme');
      return;
    }
    var bg = rgb(c.bg), gr = rgb(c.group), ac = rgb(c.button);
    var isDark = false;
    if (bg) {
      root.style.setProperty('--bg', hex(bg));
      isDark = lum(bg) < 0.3;
      root.setAttribute('data-theme', isDark ? 'dark' : 'light');
    }
    if (gr) root.style.setProperty('--group', hex(gr));
    if (ac) {
      var light = lum(ac) > 0.4;
      root.style.setProperty('--accent', hex(ac));
      root.style.setProperty('--accent-ink', light ? '#111111' : '#ffffff');
      root.style.setProperty('--accent-hover', hex(mix(ac, light ? [0, 0, 0] : [255, 255, 255], 0.16)));
      root.style.setProperty('--accent-soft', 'rgba(' + Math.round(ac[0]) + ',' + Math.round(ac[1]) + ',' + Math.round(ac[2]) + ',0.14)');
      root.style.setProperty('--accent-text', hex(mix(ac, isDark ? [255, 255, 255] : [0, 0, 0], 0.3)));
    }
  };

  try {
    var raw = localStorage.getItem('subhub-colors');
    if (raw) window.subhubApplyColors(JSON.parse(raw));
  } catch (e) {}
}

const THEME_BOOT_JS = '(' + themeBoot.toString() + ')();';

const DARK_VARS = `
  color-scheme: dark;
  --bg:#121417; --surface:#1a1d21; --surface-2:#23272d; --surface-3:#2c3137; --field:#14171a;
  --line:#2e3338; --line-soft:rgba(255,255,255,0.07);
  --text:#e4e7ea; --strong:#ffffff; --muted:#a0a8b0; --muted-2:#8a929a;
  --accent:#3b82f6; --accent-hover:#60a5fa; --accent-ink:#ffffff; --accent-soft:rgba(59,130,246,0.15); --accent-text:#8ab4fb;
  --green:#34d399; --green-soft:rgba(52,211,153,0.13); --green-text:#6ee7b7;
  --amber:#f59e0b; --amber-soft:rgba(245,158,11,0.14); --amber-text:#fcd34d;
  --red:#dc2626; --red-soft:rgba(248,113,113,0.12); --red-text:#fca5a5;
  --code:#8ab4fb; --shadow:0 8px 24px rgba(0,0,0,0.45); --shadow-sm:none;
`;

const THEME_CSS = `
:root {
  color-scheme: light;
  --bg:#f4f5f7; --surface:#ffffff; --surface-2:#f0f1f3; --surface-3:#e4e6ea; --field:#f9fafb;
  --line:#dcdfe4; --line-soft:rgba(0,0,0,0.07);
  --text:#1f2328; --strong:#0d1117; --muted:#5b636c; --muted-2:#6b737c;
  --accent:#2563eb; --accent-hover:#1d4ed8; --accent-ink:#ffffff; --accent-soft:rgba(37,99,235,0.10); --accent-text:#1d4ed8;
  --green:#15803d; --green-soft:rgba(21,128,61,0.10); --green-text:#166534;
  --amber:#b45309; --amber-soft:rgba(180,83,9,0.11); --amber-text:#92400e;
  --red:#dc2626; --red-soft:rgba(185,28,28,0.08); --red-text:#b91c1c;
  --code:#1d4ed8; --shadow:0 8px 24px rgba(0,0,0,0.12); --shadow-sm:none;
  --group: var(--surface);
  --radius:12px;
  --mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {${DARK_VARS}}
}
:root[data-theme="dark"] {${DARK_VARS}}
*, *::before, *::after { box-sizing: border-box; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
`;

const LOGO_SVG = '<svg viewBox="0 0 24 24" width="55%" height="55%" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5l8-3z"/><path d="M9 12l2 2 4-4"/></svg>';

// Tiny inline SVG favicon (shield with a check mark) used for tabs and bookmarks
const FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#2563eb"/><g transform="translate(3.6 3.6) scale(0.7)" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5l8-3z"/><path d="M9 12l2 2 4-4"/></g></svg>';
const FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,' + encodeURIComponent(FAVICON_SVG) + '">';

/* ------------------------------------------------------------------ */
/* SETUP-NEEDED SCREEN                                                 */
/* ------------------------------------------------------------------ */

function getSetupPageHTML(nonce) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Setup required · Subscription Hub</title>
${FAVICON_LINK}
<script nonce="${nonce}">${THEME_BOOT_JS}</script>
<style nonce="${nonce}">
${THEME_CSS}
body { font-family: var(--sans); background: var(--bg); color: var(--text); margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 20px; }
.card { max-width: 520px; background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 30px; }
h1 { margin: 0 0 8px; font-size: 20px; color: var(--strong); }
p, li { font-size: 14px; line-height: 1.6; color: var(--muted); }
ol { padding-left: 20px; }
code { font-family: var(--mono); background: var(--field); border: 1px solid var(--line); padding: 1px 6px; border-radius: 6px; color: var(--code); font-size: 12.5px; }
.warn { background: var(--amber-soft); color: var(--amber-text); border-radius: 10px; padding: 10px 12px; font-size: 13px; }
</style>
</head>
<body>
<main class="card">
  <h1>One quick step before you can sign in</h1>
  <p class="warn">The dashboard is locked because no secure password has been set. This protects you from leaving the default password in place.</p>
  <ol>
    <li>Edit <code>DASHBOARD_PASSWORD</code> at the top of the Worker script.</li>
    <li>Use at least ${MIN_PASSWORD_LENGTH} characters, then deploy and reload this page.</li>
  </ol>
  <p>Optional: a Worker secret named <code>ADMIN_PASSWORD</code> overrides it.</p>
</main>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* LOGIN SCREEN                                                        */
/* ------------------------------------------------------------------ */

function getLoginPageHTML(nonce) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Sign in · Subscription Hub</title>
${FAVICON_LINK}
<script nonce="${nonce}">${THEME_BOOT_JS}</script>
<style nonce="${nonce}">
${THEME_CSS}
body {
  font-family: var(--sans);
  background-color: var(--bg);
  color: var(--text); display: flex; justify-content: center; align-items: center;
  min-height: 100vh; margin: 0; padding: 20px; -webkit-font-smoothing: antialiased;
}
.card { width: 100%; max-width: 400px; padding: 36px 32px 30px; background: var(--group); border: 1px solid var(--line); border-radius: 16px; }
.logo { width: 52px; height: 52px; margin: 0 0 22px; border-radius: 12px; display: grid; place-items: center; background: var(--accent); color: var(--accent-ink); }
h1 { margin: 0 0 6px; font-size: 24px; color: var(--strong); letter-spacing: -0.02em; }
.sub { margin: 0 0 26px; font-size: 14px; color: var(--muted); }
label { display: block; font-size: 12.5px; font-weight: 600; color: var(--muted); margin-bottom: 7px; }
.field { position: relative; margin-bottom: 16px; }
input { width: 100%; padding: 13px 76px 13px 14px; background: var(--field); border: 1px solid var(--line); color: var(--strong); border-radius: 10px; font-size: 15px; font-family: inherit; transition: border-color .15s; }
input:focus { outline: none; border-color: var(--accent); }
.toggle { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); background: transparent; border: none; color: var(--muted); font-size: 12.5px; font-weight: 600; padding: 8px 10px; border-radius: 8px; cursor: pointer; font-family: inherit; }
.toggle:hover { color: var(--strong); background: var(--surface-3); }
.go { width: 100%; padding: 13px; border: none; border-radius: 10px; cursor: pointer; font-size: 15px; font-weight: 600; color: var(--accent-ink); font-family: inherit; background: var(--accent); transition: background .15s; }
.go:hover { background: var(--accent-hover); }
.go:active { transform: translateY(1px); }
.go:disabled { opacity: .6; cursor: wait; }
.err { min-height: 20px; margin-top: 12px; font-size: 13px; color: var(--red-text); }
.shake { animation: shake .35s; }
@keyframes shake { 25% { transform: translateX(-6px);} 75% { transform: translateX(6px);} }
</style>
</head>
<body>
<main class="card" id="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>Welcome back</h1>
  <p class="sub">Sign in to manage your Subscription Hub.</p>
  <form id="form">
    <label for="pass">Dashboard password</label>
    <div class="field">
      <input type="password" id="pass" autocomplete="current-password" autofocus required>
      <button type="button" class="toggle" id="toggle" aria-pressed="false">Show</button>
    </div>
    <button class="go" id="btn" type="submit">Sign in</button>
    <div class="err" id="err" role="alert" aria-live="assertive"></div>
  </form>
</main>
<script nonce="${nonce}">
(function () {
  var input = document.getElementById('pass');
  var btn = document.getElementById('btn');
  var err = document.getElementById('err');
  var toggle = document.getElementById('toggle');
  toggle.addEventListener('click', function () {
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
    input.focus();
  });
  document.getElementById('form').addEventListener('submit', async function (e) {
    e.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      var res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: input.value })
      });
      if (res.ok) { window.location.reload(); return; }
      var data = {};
      try { data = await res.json(); } catch (x) {}
      err.textContent = data.error || 'Could not sign in. Please try again.';
      var card = document.getElementById('card');
      card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
      input.select();
    } catch (x) {
      err.textContent = 'Network error. Check your connection and try again.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  });
})();
</script>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* MAIN DASHBOARD                                                      */
/* ------------------------------------------------------------------ */

function getAdminPanelHTML(nonce, baseUrl, serverGroups, rotationChunk, subToken, subTitle, rev, autoSync, lastAutoSync) {
  const boot = {
    origin: String(baseUrl),
    groups: normalizeAllGroups(serverGroups),
    chunk: Number(rotationChunk) >= 1 ? Number(rotationChunk) : DEFAULT_ROTATION_CHUNK,
    token: String(subToken || ''),
    title: String(subTitle || DEFAULT_SUB_TITLE),
    rev: String(rev || '0'),
    autoSync: String(autoSync || DEFAULT_AUTO_SYNC),
    lastAutoSync: Number(lastAutoSync) || 0
  };
  const bootJson = JSON.stringify(boot).replace(/</g, '\\u003c');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Subscription Hub</title>
${FAVICON_LINK}
<script nonce="${nonce}">${THEME_BOOT_JS}</script>
<style nonce="${nonce}">
${THEME_CSS}
html { scroll-behavior: smooth; }
body { font-family: var(--sans); background: var(--bg); color: var(--text); margin: 0; padding: 0 24px 150px; -webkit-font-smoothing: antialiased; line-height: 1.45; }
.app { max-width: 1160px; margin: 0 auto; }
.ico { display: inline-flex; align-items: center; justify-content: center; }
[hidden] { display: none !important; }

/* Top bar */
.topbar { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; padding: 22px 0 20px; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-logo { width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center; background: var(--accent); color: var(--accent-ink); }
h1 { margin: 0; font-size: 18px; color: var(--strong); letter-spacing: -0.01em; }
.brand-sub { font-size: 12.5px; color: var(--muted); margin-top: 1px; }
.top-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.status-pill { display: inline-flex; align-items: center; gap: 8px; font-size: 12.5px; font-weight: 600; color: var(--muted); background: var(--surface); border: 1px solid var(--line); border-radius: 999px; padding: 7px 13px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); display: inline-block; }
.dot.dirty { background: var(--amber); }
.status-text.dirty { color: var(--amber-text); }

/* Layout: settings rail on the left, work area on the right */
.layout { display: grid; grid-template-columns: 340px minmax(0, 1fr); gap: 24px; align-items: start; }
.side { position: sticky; top: 16px; display: flex; flex-direction: column; gap: 14px; max-height: calc(100vh - 32px); overflow-y: auto; padding: 2px; }
.side > * { flex-shrink: 0; }
.main { min-width: 0; }

/* Buttons */
.btn { background: var(--accent); color: var(--accent-ink); border: 1px solid transparent; padding: 0 15px; min-height: 38px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13.5px; font-family: inherit; transition: background .15s, transform .1s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; gap: 7px; text-decoration: none; }
.btn:hover { background: var(--accent-hover); }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: .45; cursor: not-allowed; transform: none; }
.btn-ghost { background: transparent; border-color: var(--line); color: var(--text); }
.btn-ghost:hover { background: var(--surface-2); }
.btn-danger { background: var(--red); color: #fff; }
.btn-danger:hover { background: #b91c1c; }
.btn-sm { min-height: 32px; padding: 0 11px; font-size: 12.5px; border-radius: 8px; }
.icon-btn { background: transparent; border: 1px solid var(--line); color: var(--muted); width: 36px; height: 36px; border-radius: 8px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; padding: 0; transition: background .15s, color .15s; }
.icon-btn:hover:not(:disabled) { background: var(--surface-2); color: var(--strong); }
.icon-btn:disabled { opacity: .3; cursor: default; }
.icon-btn.danger:hover:not(:disabled) { background: var(--red-soft); color: var(--red-text); border-color: var(--red); }

/* Cards */
.card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; }
.card-title { font-size: 14px; font-weight: 700; color: var(--strong); display: flex; align-items: center; gap: 8px; margin: 0; letter-spacing: -0.005em; }
.card-title.sm { font-size: 13px; }
.card-desc { font-size: 12.5px; color: var(--muted); margin-top: 4px; line-height: 1.55; }
.card-section + .card-section { margin-top: 18px; padding-top: 18px; border-top: 1px solid var(--line); }

/* Overview numbers */
.overview { display: grid; grid-template-columns: repeat(3, 1fr); padding: 0; overflow: hidden; }
.stat { padding: 14px 16px; }
.stat + .stat { border-left: 1px solid var(--line); }
.stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted-2); font-weight: 700; }
.stat-value { font-size: 26px; font-weight: 700; color: var(--strong); margin-top: 3px; letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }

/* Subscription link */
.link-row { margin-top: 12px; display: flex; align-items: center; gap: 8px; background: var(--field); border: 1px solid var(--line); border-radius: 8px; padding: 6px 6px 6px 12px; }
.link-row code { color: var(--code); font-family: var(--mono); font-size: 12.5px; word-break: break-all; flex: 1; min-width: 0; }
.link-actions { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; margin-top: 10px; }
.link-subactions { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.banner { margin-top: 12px; display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; background: var(--amber-soft); color: var(--amber-text); border-radius: 8px; padding: 10px 12px; font-size: 12.5px; line-height: 1.5; }

/* Form bits */
.field-label { display: block; font-size: 12.5px; font-weight: 600; color: var(--muted); margin: 14px 0 6px; }
.field-label.first { margin-top: 12px; }
.text-input { width: 100%; background: var(--field); border: 1px solid var(--line); color: var(--strong); border-radius: 8px; padding: 10px 12px; font-size: 14px; font-family: inherit; transition: border-color .15s; }
.text-input:focus { outline: none; border-color: var(--accent); }

/* Colour settings */
.palette-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; }
.palette-btn { display: flex; align-items: center; justify-content: space-between; gap: 8px; background: transparent; border: 1px solid var(--line); color: var(--text); border-radius: 8px; padding: 8px 10px; font-size: 12.5px; font-weight: 600; font-family: inherit; cursor: pointer; transition: background .15s, border-color .15s; }
.palette-btn:hover { background: var(--surface-2); }
.palette-btn.active { border-color: var(--accent); box-shadow: inset 0 0 0 1px var(--accent); }
.swatches { display: inline-flex; }
.swatch { width: 14px; height: 14px; border-radius: 50%; border: 1px solid rgba(127,127,127,.45); margin-left: -4px; }
.swatch:first-child { margin-left: 0; }
.color-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 12px; }
.color-field { display: flex; flex-direction: column; gap: 6px; font-size: 12px; color: var(--muted); font-weight: 600; }
.color-field input[type="color"] { width: 100%; height: 38px; padding: 2px; background: var(--field); border: 1px solid var(--line); border-radius: 8px; cursor: pointer; }
.color-actions { margin-top: 12px; display: flex; justify-content: flex-end; }

/* Rotation & Segmented buttons */
.segmented { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 10px; }
.preset, .sync-opt { background: transparent; border: 1px solid var(--line); color: var(--text); min-width: 38px; min-height: 34px; padding: 0 11px; border-radius: 8px; font-size: 13px; font-weight: 700; cursor: pointer; transition: all .15s; font-family: inherit; }
.preset:hover, .sync-opt:hover { background: var(--surface-2); }
.preset.active, .sync-opt.active { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.sync-opt { flex: 1; font-weight: 600; }
.custom-wrap { display: flex; align-items: center; gap: 6px; background: var(--field); border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; min-height: 34px; }
.custom-wrap label { font-size: 12px; color: var(--muted); }
.custom-wrap input { width: 48px; background: transparent; border: none; color: var(--strong); font-size: 13.5px; font-weight: 700; text-align: center; font-family: inherit; }
.custom-wrap input:focus { outline: none; }
.custom-wrap:focus-within { border-color: var(--accent); }
.rotation-example { margin-top: 10px; font-size: 12.5px; color: var(--muted); line-height: 1.55; }
.rotation-example b { color: var(--text); }
.disclosure { margin-top: 12px; width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 10px; background: transparent; border: none; border-top: 1px dashed var(--line); padding: 12px 0 0; cursor: pointer; color: var(--text); font-family: inherit; font-size: 13px; font-weight: 600; text-align: left; }
.disclosure.no-border { margin-top: 0; border-top: none; padding-top: 0; }
.disclosure .left { display: inline-flex; align-items: center; gap: 8px; }
.disclosure .chev { transition: transform .18s; color: var(--muted); }
.disclosure[aria-expanded="true"] .chev { transform: rotate(90deg); }
.disclosure .meta { font-size: 12px; font-weight: 500; color: var(--muted); }
.preview-body { margin-top: 10px; }
.preview-legend { font-size: 12px; color: var(--muted); margin-bottom: 8px; line-height: 1.5; }
.batches { display: flex; flex-wrap: wrap; gap: 6px; }
.batch-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 999px; color: var(--text); background: var(--group); border: 1px solid var(--line); }
.batch-pill b { font-family: var(--mono); }
.batch-pill.partial { border-style: dashed; border-color: var(--amber); }
.batch-sep { color: var(--muted-2); font-size: 11px; align-self: center; }
.batch-more { font-size: 12px; color: var(--muted); align-self: center; }

/* Groups toolbar & search */
.groups-toolbar { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; flex-wrap: wrap; margin: 0 2px 12px; }
.groups-toolbar h2 { margin: 0; font-size: 20px; color: var(--strong); letter-spacing: -0.02em; }
.groups-toolbar p { margin: 3px 0 0; font-size: 13px; color: var(--muted); }
.toolbar-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.filter-bar { display: flex; align-items: center; gap: 8px; margin: 0 2px 14px; flex-wrap: wrap; }
.search-wrap { position: relative; flex: 1; min-width: 200px; }
.search-input { width: 100%; background: var(--surface); border: 1px solid var(--line); color: var(--strong); border-radius: 8px; padding: 8px 32px 8px 12px; font-size: 13px; font-family: inherit; }
.search-input:focus { outline: none; border-color: var(--accent); }
.search-clear { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); background: transparent; border: none; color: var(--muted); cursor: pointer; font-size: 14px; padding: 4px 6px; border-radius: 6px; }
.search-clear:hover { color: var(--strong); background: var(--surface-2); }

/* Group cards: use the "groups" colour */
.server-group { background: var(--group); border: 1px solid var(--line); border-radius: var(--radius); padding: 14px 16px 14px; transition: border-color .15s, opacity .15s; }
.server-group:hover { border-color: var(--muted-2); }
.server-group.dragging { opacity: .35; }
.server-group.collapsed .group-body { display: none; }
.server-group.collapsed .group-header { margin-bottom: 0; }
.server-group.is-disabled { opacity: .62; border-style: dashed; }
.server-group.is-disabled .avatar { background: var(--surface-3); color: var(--muted); }
.drop-zone { position: relative; height: 14px; border-radius: 8px; border: 2px dashed transparent; display: flex; align-items: center; justify-content: center; transition: background-color .1s, border-color .1s; }
body.is-dragging .drop-zone { border-color: var(--line); }
body.is-dragging .drop-zone.hover { border-color: var(--accent); border-style: solid; background: var(--accent-soft); }
.drop-zone::after { content: ''; font-size: 11px; letter-spacing: .4px; color: transparent; }
body.is-dragging .drop-zone.hover::after { content: 'Drop here'; color: var(--accent-text); font-weight: 700; }
/* "Add group here" button that appears in the gap between groups */
.drop-zone::before { content: ''; position: absolute; left: 0; right: 0; top: -8px; bottom: -8px; }
.insert-btn { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: 2; height: 26px; padding: 0 12px; border-radius: 999px; border: 1px solid var(--accent); background: var(--bg); color: var(--accent-text); font-size: 12px; font-weight: 700; font-family: inherit; cursor: pointer; opacity: 0; transition: opacity .15s, background .15s; white-space: nowrap; }
.drop-zone:hover .insert-btn, .insert-btn:focus-visible { opacity: 1; }
.insert-btn:hover { background: var(--accent); color: var(--accent-ink); }
body.is-dragging .insert-btn { display: none; }
@media (hover: none) { .insert-btn { opacity: .85; } }
.group-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
.header-left { display: flex; align-items: center; gap: 6px; flex: 1; min-width: 220px; }
.header-right { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.drag-handle { color: var(--muted-2); user-select: none; cursor: grab; padding: 6px 2px; border-radius: 6px; display: inline-flex; }
.drag-handle:hover { color: var(--text); background: var(--surface-2); }
.drag-handle:active { cursor: grabbing; }
.collapse-btn { background: none; border: none; color: var(--muted); cursor: pointer; padding: 8px; border-radius: 8px; display: inline-flex; }
.collapse-btn:hover { background: var(--surface-2); color: var(--strong); }
.collapse-btn .chev { transition: transform .18s; }
.server-group:not(.collapsed) .collapse-btn .chev { transform: rotate(90deg); }
.avatar { width: 34px; height: 34px; flex: none; border-radius: 8px; display: grid; place-items: center; background: var(--accent); color: var(--accent-ink); font-weight: 800; font-size: 15px; text-transform: uppercase; }
.group-title { background: transparent; border: none; color: var(--strong); font-size: 16px; font-weight: 700; border-bottom: 1px dashed transparent; padding: 4px 2px; flex: 1; min-width: 0; font-family: inherit; letter-spacing: -0.01em; }
.group-title:hover { border-bottom-color: var(--line); }
.group-title:focus { outline: none; border-bottom-color: var(--accent); }
.badge { background: var(--surface-2); color: var(--muted); font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 999px; white-space: nowrap; }
.badge.empty { background: var(--red-soft); color: var(--red-text); }
.badge.sub-mode { background: var(--green-soft); color: var(--green-text); }
.badge.paused { background: var(--amber-soft); color: var(--amber-text); }

.enable-btn { background: var(--surface-2); border: 1px solid var(--line); color: var(--text); font-size: 12px; font-weight: 700; min-height: 32px; padding: 0 10px; border-radius: 8px; cursor: pointer; font-family: inherit; display: inline-flex; align-items: center; gap: 6px; }
.enable-btn:hover { background: var(--surface-3); }
.enable-btn .state-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); }
.enable-btn.off .state-dot { background: var(--muted-2); }
.enable-btn.off { color: var(--muted); }

.chips { display: flex; flex-wrap: wrap; gap: 5px; margin: 0 0 10px; }
.chips:empty { display: none; }
.chip { font-family: var(--mono); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; padding: 2px 7px; border-radius: 6px; background: var(--surface-2); color: var(--muted); }
.chip.v6 { background: var(--accent-soft); color: var(--accent-text); }

.mode-bar { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
.mode-switch-group { display: inline-flex; background: var(--surface-2); border-radius: 10px; padding: 3px; gap: 3px; }
.mode-btn { background: transparent; border: none; color: var(--muted); font-size: 12.5px; font-weight: 700; min-height: 30px; padding: 0 13px; border-radius: 8px; cursor: pointer; transition: all .15s; font-family: inherit; }
.mode-btn:hover { color: var(--strong); }
.mode-btn.active { background: var(--surface); color: var(--strong); }
.mode-btn.active.sub-active { color: var(--green-text); }
.sub-actions-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sub-status-text { font-size: 12px; color: var(--muted); }
.sub-status-text.ok { color: var(--green-text); }
.sub-status-text.err { color: var(--red-text); }

textarea { width: 100%; height: 130px; background: var(--field); border: 1px solid var(--line); border-radius: 8px; color: var(--text); padding: 11px 13px; font-family: var(--mono); font-size: 12.5px; line-height: 1.55; resize: vertical; transition: border-color .15s; }
textarea.sub-textarea { height: 90px; }
textarea:focus { outline: none; border-color: var(--accent); }
body.is-dragging textarea, body.is-dragging input, body.is-dragging .save-bar { pointer-events: none; }

.group-footer { margin-top: 9px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; color: var(--muted-2); }
.group-footer code { color: var(--muted); font-family: var(--mono); font-size: 11.5px; }
.warn-text { color: var(--amber-text); font-weight: 600; }
.empty-groups-state { background: var(--group); border: 1px dashed var(--line); border-radius: var(--radius); padding: 52px 20px; text-align: center; color: var(--muted); }
.empty-groups-state p { margin: 0 0 14px; font-size: 14px; line-height: 1.55; }

/* Floating save bar (only shown while there are unsaved changes) */
.save-bar { position: fixed; left: 50%; bottom: 22px; z-index: 40; transform: translate(-50%, 18px); opacity: 0; visibility: hidden; display: flex; align-items: center; gap: 14px; flex-wrap: wrap; justify-content: center; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 10px 10px 10px 18px; box-shadow: var(--shadow); transition: opacity .2s, transform .2s, visibility .2s; max-width: calc(100vw - 24px); }
.save-bar.show { opacity: 1; visibility: visible; transform: translate(-50%, 0); }
.save-label { font-size: 13px; color: var(--muted); font-weight: 600; }
.save-actions { display: flex; align-items: center; gap: 8px; }
kbd { font-family: var(--mono); font-size: 10.5px; background: rgba(127,127,127,.25); border-radius: 5px; padding: 1px 5px; }

/* Toasts */
.toasts { position: fixed; top: 18px; right: 18px; z-index: 100; display: flex; flex-direction: column; gap: 8px; max-width: calc(100vw - 36px); }
.toast { background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--accent); color: var(--text); padding: 10px 12px 10px 15px; border-radius: 10px; font-size: 13.5px; font-weight: 500; box-shadow: var(--shadow); animation: toastIn .22s ease-out; display: flex; align-items: center; gap: 12px; }
.toast.ok { border-left-color: var(--green); }
.toast.err { border-left-color: var(--red); }
.toast .toast-action { background: var(--accent-soft); color: var(--accent-text); border: none; border-radius: 8px; padding: 6px 11px; font-weight: 700; font-size: 12.5px; cursor: pointer; font-family: inherit; }
.toast.out { opacity: 0; transform: translateX(14px); transition: all .22s; }
@keyframes toastIn { from { opacity: 0; transform: translateX(14px); } to { opacity: 1; transform: none; } }

/* Dialog & QR modal */
dialog.dlg { border: 1px solid var(--line); background: var(--surface); color: var(--text); border-radius: 14px; padding: 24px; max-width: 440px; width: calc(100vw - 32px); box-shadow: var(--shadow); }
dialog.dlg::backdrop { background: rgba(0,0,0,.5); }
dialog.dlg h3 { margin: 0 0 8px; font-size: 17px; color: var(--strong); }
dialog.dlg p { margin: 0 0 20px; font-size: 14px; line-height: 1.6; color: var(--muted); }
.dlg-actions { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
.qr-box { display: grid; place-items: center; background: #ffffff; border: 1px solid var(--line); border-radius: 12px; padding: 18px; margin: 12px 0 18px; }
.qr-box svg { width: 220px; height: 220px; display: block; }

@media (max-width: 940px) {
  .layout { grid-template-columns: 1fr; }
  .side { position: static; max-height: none; overflow: visible; }
}
@media (max-width: 620px) {
  body { padding: 0 12px 170px; }
  .btn { min-height: 42px; }
  .btn-sm { min-height: 38px; }
  .icon-btn { width: 42px; height: 42px; }
  .server-group { padding: 12px 12px; }
  .status-pill { order: 3; }
  kbd { display: none; }
  .save-bar { left: 12px; right: 12px; bottom: 12px; transform: translateY(18px); max-width: none; padding: 10px 12px; }
  .save-bar.show { transform: none; }
  .save-actions { width: 100%; }
  .save-actions .btn { flex: 1; }
}
</style>
</head>
<body>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>

<div class="app">
  <header class="topbar">
    <div class="brand">
      <div class="brand-logo">${LOGO_SVG}</div>
      <div>
        <h1>Config Manager</h1>
        <div class="brand-sub">Group, rotate and publish your subscription</div>
      </div>
    </div>
    <div class="top-actions">
      <span class="status-pill"><span class="dot" id="dirtyDot"></span><span class="status-text" id="saveStatusText">All changes saved</span></span>
      <button class="btn btn-ghost" id="signOutBtn" type="button">Sign out</button>
      <button class="btn" id="addGroupTop" type="button">+ Add group</button>
    </div>
  </header>

  <div class="layout">
    <aside class="side" aria-label="Subscription link and settings">
      <section class="card overview" aria-label="Summary">
        <div class="stat"><div class="stat-label">Configs</div><div class="stat-value" id="statConfigs">0</div></div>
        <div class="stat"><div class="stat-label">Groups</div><div class="stat-value" id="statGroups">0</div></div>
        <div class="stat"><div class="stat-label">Batches</div><div class="stat-value" id="statBatches">0</div></div>
      </section>

      <section class="card" aria-labelledby="linkTitle">
        <h2 class="card-title" id="linkTitle">Your subscription link</h2>
        <div class="card-desc">Paste this into your app. External subscription links inside your groups sync automatically every time your app updates this link.</div>
        <div class="link-row">
          <code id="subUrl"></code>
          <button class="btn btn-ghost btn-sm" id="toggleLinkBtn" type="button" aria-pressed="false">Show</button>
        </div>
        <div class="banner" id="legacyBanner" hidden>
          <span>This link uses a short legacy code that could be guessed. Create a new one to make it much safer.</span>
          <button class="btn btn-sm" id="upgradeLinkBtn" type="button">Upgrade link</button>
        </div>
        <div class="link-actions">
          <button class="btn" id="copySubBtn" type="button">Copy link</button>
          <button class="btn btn-ghost" id="qrSubBtn" type="button" title="Show QR code for mobile apps">QR code</button>
          <button class="btn btn-ghost" id="regenTokenBtn" type="button">New link</button>
        </div>
        <div class="link-subactions">
          <a class="btn btn-ghost btn-sm" id="openPlainBtn" href="#" target="_blank" rel="noopener">Preview plain output ↗</a>
        </div>
      </section>

      <section class="card" id="settingsCard" aria-labelledby="settingsTitle">
        <h2 class="card-title" id="settingsTitle">Settings</h2>

        <div class="card-section">
          <label class="field-label first" for="subTitleInput">Subscription name</label>
          <input class="text-input" type="text" id="subTitleInput" maxlength="100" placeholder="Subscription name" autocomplete="off">
          <div class="card-desc">Apps show this as the name of your subscription. They pick up changes on their next refresh.</div>
        </div>

        <div class="card-section">
          <h3 class="card-title sm" id="autoSyncTitle">Scheduled background sync</h3>
          <div class="card-desc">External links always sync live when your client app updates. You can also turn on a background schedule:</div>
          <div class="segmented" role="group" aria-labelledby="autoSyncTitle">
            <button type="button" class="sync-opt" data-sync="off">Off</button>
            <button type="button" class="sync-opt" data-sync="daily">Daily</button>
            <button type="button" class="sync-opt" data-sync="weekly">Weekly</button>
          </div>
          <div class="card-desc" id="autoSyncHint" style="margin-top:8px;"></div>
        </div>

        <div class="card-section">
          <h3 class="card-title sm" id="rotationTitle">Configs per group, per round</h3>
          <div class="card-desc" id="divideHintText"></div>
          <div class="segmented" role="group" aria-labelledby="rotationTitle">
            <button type="button" class="preset" data-chunk="1">1</button>
            <button type="button" class="preset" data-chunk="2">2</button>
            <button type="button" class="preset" data-chunk="3">3</button>
            <button type="button" class="preset" data-chunk="5">5</button>
            <button type="button" class="preset" data-chunk="10">10</button>
            <div class="custom-wrap">
              <label for="customChunkInput">Custom</label>
              <input type="number" id="customChunkInput" min="1" max="500" inputmode="numeric">
            </div>
          </div>
          <div class="rotation-example" id="rotationExample"></div>
          <button class="disclosure" id="previewToggle" type="button" aria-expanded="false" aria-controls="previewBody">
            <span class="left"><span class="ico chev" id="previewChev"></span><span>Preview output order</span></span>
            <span class="meta" id="previewSummary"></span>
          </button>
          <div class="preview-body" id="previewBody" hidden>
            <div class="preview-legend">Each pill is one batch, in the order your app will list them. A dashed outline means that group ran out of configs (its last, smaller batch).</div>
            <div class="batches" id="batches"></div>
          </div>
        </div>

        <div class="card-section">
          <button class="disclosure no-border" id="colorsToggle" type="button" aria-expanded="false" aria-controls="colorsBody">
            <span class="left"><span class="ico chev" id="colorsChev"></span><span>Appearance &amp; colors</span></span>
            <span class="meta" id="colorsMeta">System / custom</span>
          </button>
          <div id="colorsBody" hidden style="margin-top:10px;">
            <div class="card-desc">Pick a preset or choose your own. Saved in this browser only.</div>
            <div class="palette-row" id="palettes" role="group" aria-label="Color presets"></div>
            <div class="color-grid">
              <label class="color-field"><span>Background</span><input type="color" id="colorBg"></label>
              <label class="color-field"><span>Groups</span><input type="color" id="colorGroup"></label>
              <label class="color-field"><span>Buttons</span><input type="color" id="colorButton"></label>
            </div>
            <div class="color-actions"><button class="btn btn-ghost btn-sm" id="resetColorsBtn" type="button">Reset to default</button></div>
          </div>
        </div>
      </section>
    </aside>

    <main class="main">
      <div class="groups-toolbar">
        <div>
          <h2>Server groups</h2>
          <p>Paste direct configs or a subscription link into each group. Pause, reorder or sync anytime.</p>
        </div>
        <div class="toolbar-actions">
          <button class="btn btn-ghost btn-sm" id="syncAllBtn" type="button">Sync all links</button>
          <button class="btn btn-ghost btn-sm" id="collapseAllBtn" type="button">Collapse all</button>
          <button class="btn btn-ghost btn-sm" id="expandAllBtn" type="button">Expand all</button>
          <button class="btn btn-sm" id="addGroupList" type="button">+ Add group</button>
        </div>
      </div>
      <div class="filter-bar">
        <div class="search-wrap">
          <input type="search" class="search-input" id="groupFilterInput" placeholder="Filter groups by name or protocol (e.g. Germany, vless, ipv6)…" autocomplete="off">
          <button type="button" class="search-clear" id="clearFilterBtn" hidden title="Clear filter">✕</button>
        </div>
      </div>
      <div id="groupsContainer"></div>
    </main>
  </div>
</div>

<div class="save-bar" id="saveBar" role="region" aria-label="Unsaved changes">
  <span class="save-label" id="floatingTotalText">0 configs in 0 groups</span>
  <div class="save-actions">
    <button class="btn btn-ghost" id="discardBtn" type="button" hidden>Discard</button>
    <button class="btn" id="saveAllBtn" type="button">Save changes <kbd>Ctrl S</kbd></button>
  </div>
</div>

<script type="application/json" id="boot">${bootJson}</script>
<script nonce="${nonce}">
(function () {
  'use strict';

  var boot = JSON.parse(document.getElementById('boot').textContent);
  var NEWLINE = String.fromCharCode(10);
  var SCHEME_RE = new RegExp('^[a-z][a-z0-9+.-]*://', 'i');
  var SAVE_LABEL = 'Save changes <kbd>Ctrl S</kbd>';

  var BASE_ORIGIN = boot.origin;
  var dataGroups = boot.groups;
  var currentRotationChunk = boot.chunk;
  var currentSubToken = boot.token;
  var currentSubTitle = boot.title;
  var currentRev = boot.rev;
  var currentAutoSync = boot.autoSync || 'off';
  var lastAutoSyncTime = boot.lastAutoSync || 0;

  var collapsed = new Set();
  var linkVisible = false;
  var hasUnsavedChanges = false;
  var saving = false;
  var currentFilter = '';

  var dragFromIndex = null;
  var dropPosition = null;
  var dragPointerX = 0;
  var dragPointerY = 0;
  var dragScrollRAF = null;

  function $(id) { return document.getElementById(id); }

  /* ---------- tiny DOM + icon helpers ---------- */
  var ICONS = {
    chev: '<path d="M9 6l6 6-6 6"/>',
    up: '<path d="M12 19V5M5 12l7-7 7 7"/>',
    down: '<path d="M12 5v14M19 12l-7 7-7-7"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    grip: '<g fill="currentColor" stroke="none"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></g>'
  };
  function icon(name, size) {
    var s = document.createElement('span');
    s.className = 'ico';
    var px = size || 16;
    s.innerHTML = '<svg viewBox="0 0 24 24" width="' + px + '" height="' + px + '" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[name] + '</svg>';
    return s;
  }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === false || v === null || v === undefined) return;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    });
    (kids || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }
  function display(name) { return String(name).replace(/_/g, ' '); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

  function formatAgo(ts) {
    var n = Number(ts) || 0;
    if (n <= 0) return '';
    var diffSec = Math.max(0, Math.floor((Date.now() - n) / 1000));
    if (diffSec < 45) return 'just now';
    var mins = Math.floor(diffSec / 60);
    if (mins < 60) return mins + 'm ago';
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    var days = Math.floor(hrs / 24);
    return days + 'd ago';
  }

  /* ---------- Zero-dependency QR Code SVG generator (Byte mode, ECC-L, V1-V8) ---------- */
  function buildQrSvg(text) {
    var data = Array.from(new TextEncoder().encode(String(text || '')));
    // [totalCodewords, dataCodewords, numBlocks] for Versions 1..8 at ECC Level L
    var VERSIONS = [
      null,
      [26, 19, 1], [44, 34, 1], [70, 55, 1], [100, 80, 1],
      [134, 108, 1], [172, 136, 2], [196, 156, 2], [242, 194, 2]
    ];
    var ver = 1;
    while (ver <= 8 && data.length + 2 > VERSIONS[ver][1]) ver++;
    if (ver > 8) return null;

    var vInfo = VERSIONS[ver];
    var totalCw = vInfo[0], dataCw = vInfo[1], blocks = vInfo[2];
    var eccCwPerBlock = (totalCw - dataCw) / blocks;
    var dataCwPerBlock = dataCw / blocks;

    var bits = [];
    function pushBits(val, len) {
      for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
    }
    pushBits(4, 4); // Byte mode
    pushBits(data.length, 8);
    data.forEach(function (b) { pushBits(b, 8); });
    var maxBits = dataCw * 8;
    pushBits(0, Math.min(4, maxBits - bits.length));
    while (bits.length % 8 !== 0) bits.push(0);
    var cw = [];
    for (var i = 0; i < bits.length; i += 8) {
      var byte = 0;
      for (var j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      cw.push(byte);
    }
    var padIdx = 0;
    while (cw.length < dataCw) { cw.push(padIdx % 2 === 0 ? 0xEC : 0x11); padIdx++; }

    // GF(256) math for Reed-Solomon
    var exp = new Uint8Array(512), log = new Uint8Array(256);
    var x = 1;
    for (var i = 0; i < 255; i++) {
      exp[i] = x; log[x] = i;
      x = (x << 1) ^ ((x & 0x80) ? 0x11D : 0);
    }
    for (var i = 255; i < 512; i++) exp[i] = exp[i - 255];
    function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : exp[log[a] + log[b]]; }

    var gen = [1];
    for (var i = 0; i < eccCwPerBlock; i++) {
      var next = new Array(gen.length + 1).fill(0);
      for (var j = 0; j < gen.length; j++) {
        next[j] ^= gen[j];
        next[j + 1] ^= gfMul(gen[j], exp[i]);
      }
      gen = next;
    }

    var dataBlocks = [], eccBlocks = [];
    for (var b = 0; b < blocks; b++) {
      var slice = cw.slice(b * dataCwPerBlock, (b + 1) * dataCwPerBlock);
      dataBlocks.push(slice);
      var rem = new Array(eccCwPerBlock).fill(0);
      slice.forEach(function (byte) {
        var factor = byte ^ rem.shift();
        rem.push(0);
        for (var j = 0; j < eccCwPerBlock; j++) rem[j] ^= gfMul(gen[j + 1], factor);
      });
      eccBlocks.push(rem);
    }

    var finalCw = [];
    for (var i = 0; i < dataCwPerBlock; i++) for (var b = 0; b < blocks; b++) finalCw.push(dataBlocks[b][i]);
    for (var i = 0; i < eccCwPerBlock; i++) for (var b = 0; b < blocks; b++) finalCw.push(eccBlocks[b][i]);

    var size = ver * 4 + 17;
    var mat = Array.from({ length: size }, function () { return new Array(size).fill(null); });
    var isFunc = Array.from({ length: size }, function () { return new Array(size).fill(false); });

    function setMod(r, c, val) {
      if (r >= 0 && r < size && c >= 0 && c < size) { mat[r][c] = !!val; isFunc[r][c] = true; }
    }
    function finder(r, c) {
      for (var dy = -1; dy <= 7; dy++) for (var dx = -1; dx <= 7; dx++) {
        var inOuter = (dy >= 0 && dy <= 6 && dx >= 0 && dx <= 6);
        var onRing = (dy === 0 || dy === 6 || dx === 0 || dx === 6);
        var inCore = (dy >= 2 && dy <= 4 && dx >= 2 && dx <= 4);
        setMod(r + dy, c + dx, inOuter && (onRing || inCore));
      }
    }
    finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
    for (var i = 8; i < size - 8; i++) { setMod(6, i, i % 2 === 0); setMod(i, 6, i % 2 === 0); }

    var ALIGN = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42]][ver];
    for (var i = 0; i < ALIGN.length; i++) for (var j = 0; j < ALIGN.length; j++) {
      var ar = ALIGN[i], ac = ALIGN[j];
      if (isFunc[ar][ac]) continue;
      for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) {
        setMod(ar + dy, ac + dx, Math.max(Math.abs(dy), Math.abs(dx)) !== 1);
      }
    }
    for (var i = 0; i < 9; i++) {
      if (i !== 6) { setMod(8, i, false); setMod(i, 8, false); }
      if (i < 8) { setMod(8, size - 1 - i, false); setMod(size - 1 - i, 8, false); }
    }
    setMod(size - 8, 8, true);

    var allBits = [];
    finalCw.forEach(function (byte) { for (var i = 7; i >= 0; i--) allBits.push((byte >>> i) & 1); });
    var bitIdx = 0, up = true;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        var r = up ? (size - 1 - vert) : vert;
        for (var j = 0; j < 2; j++) {
          var c = right - j;
          if (!isFunc[r][c]) {
            var dark = bitIdx < allBits.length ? (allBits[bitIdx++] === 1) : false;
            if ((r + c) % 2 === 0) dark = !dark; // mask 0
            mat[r][c] = dark;
          }
        }
      }
      up = !up;
    }

    // Format bits for ECC Level L (01) + Mask 0 (000) -> 0x77c4
    var fmt = 0x77c4;
    for (var i = 0; i <= 5; i++) setMod(8, i, ((fmt >>> i) & 1) === 1);
    setMod(8, 7, ((fmt >>> 6) & 1) === 1);
    setMod(8, 8, ((fmt >>> 7) & 1) === 1);
    setMod(7, 8, ((fmt >>> 8) & 1) === 1);
    for (var i = 9; i < 15; i++) setMod(14 - i, 8, ((fmt >>> i) & 1) === 1);
    for (var i = 0; i < 8; i++) setMod(8, size - 1 - i, ((fmt >>> i) & 1) === 1);
    for (var i = 8; i < 15; i++) setMod(size - 15 + i, 8, ((fmt >>> i) & 1) === 1);

    var path = '';
    for (var r = 0; r < size; r++) for (var c = 0; c < size; c++) {
      if (mat[r][c]) path += 'M' + (c + 2) + ',' + (r + 2) + 'h1v1h-1z';
    }
    var view = size + 4;
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + view + ' ' + view + '" shape-rendering="crispEdges"><rect width="' + view + '" height="' + view + '" fill="#fff"/><path d="' + path + '" fill="#000"/></svg>';
  }

  /* ---------- colour settings (saved in this browser) ---------- */
  var COLOR_PRESETS = [
    { name: 'Light', bg: '#f4f5f7', group: '#ffffff', button: '#2563eb' },
    { name: 'Dark',  bg: '#121417', group: '#1c2026', button: '#3b82f6' },
    { name: 'Sand',  bg: '#f6f3ec', group: '#fffdf8', button: '#0f766e' },
    { name: 'Mint',  bg: '#edf5f0', group: '#ffffff', button: '#15803d' }
  ];
  var colors = null;

  function currentTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    if (t) return t;
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  function loadColors() {
    try {
      var raw = localStorage.getItem('subhub-colors');
      if (raw) {
        var c = JSON.parse(raw);
        if (c && c.bg && c.group && c.button) return { bg: c.bg, group: c.group, button: c.button };
      }
    } catch (e) {}
    return null;
  }
  function saveColors() {
    try {
      if (colors) localStorage.setItem('subhub-colors', JSON.stringify(colors));
      else localStorage.removeItem('subhub-colors');
    } catch (e) {}
  }
  function shownColors() {
    if (colors) return colors;
    var p = COLOR_PRESETS[currentTheme() === 'dark' ? 1 : 0];
    return { bg: p.bg, group: p.group, button: p.button };
  }
  function refreshColorUI() {
    var c = shownColors();
    $('colorBg').value = c.bg;
    $('colorGroup').value = c.group;
    $('colorButton').value = c.button;
    var activePresetName = colors ? 'Custom' : 'System default';
    document.querySelectorAll('.palette-btn').forEach(function (b) {
      var p = COLOR_PRESETS[parseInt(b.getAttribute('data-i'), 10)];
      var on = !!colors && p.bg === c.bg && p.group === c.group && p.button === c.button;
      if (on) activePresetName = p.name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    $('colorsMeta').textContent = activePresetName;
  }
  function setColors(next) {
    colors = next;
    if (window.subhubApplyColors) window.subhubApplyColors(colors);
    saveColors();
    refreshColorUI();
  }
  function initColors() {
    colors = loadColors();
    var box = $('palettes');
    COLOR_PRESETS.forEach(function (p, i) {
      var sw = h('span', { 'class': 'swatches', 'aria-hidden': 'true' }, [
        h('span', { 'class': 'swatch' }), h('span', { 'class': 'swatch' }), h('span', { 'class': 'swatch' })
      ]);
      sw.children[0].style.background = p.bg;
      sw.children[1].style.background = p.group;
      sw.children[2].style.background = p.button;
      var btn = h('button', { type: 'button', 'class': 'palette-btn', 'data-i': String(i) }, [h('span', { text: p.name }), sw]);
      btn.addEventListener('click', function () { setColors({ bg: p.bg, group: p.group, button: p.button }); });
      box.appendChild(btn);
    });
    function onPick(key) {
      return function (e) {
        var c = Object.assign({}, shownColors());
        c[key] = e.target.value;
        setColors(c);
      };
    }
    $('colorBg').addEventListener('input', onPick('bg'));
    $('colorGroup').addEventListener('input', onPick('group'));
    $('colorButton').addEventListener('input', onPick('button'));
    $('resetColorsBtn').addEventListener('click', function () { setColors(null); showToast('Colors reset', 'ok'); });
    refreshColorUI();
  }

  /* ---------- toasts & dialogs ---------- */
  function showToast(message, type, opts) {
    opts = opts || {};
    var box = $('toasts');
    var t = h('div', { 'class': 'toast' + (type ? ' ' + type : '') }, [h('span', { text: message })]);
    var timer;
    function dismiss() {
      clearTimeout(timer);
      t.classList.add('out');
      setTimeout(function () { t.remove(); }, 250);
    }
    if (opts.actionLabel) {
      t.appendChild(h('button', {
        type: 'button', 'class': 'toast-action', text: opts.actionLabel,
        onclick: function () { dismiss(); if (opts.onAction) opts.onAction(); }
      }));
    }
    box.appendChild(t);
    timer = setTimeout(dismiss, opts.duration || 3200);
  }

  function choose(opts) {
    return new Promise(function (resolve) {
      var result = opts.dismissValue;
      var dlg = h('dialog', { 'class': 'dlg', 'aria-labelledby': 'dlgTitle' });
      dlg.appendChild(h('h3', { id: 'dlgTitle', text: opts.title }));
      dlg.appendChild(h('p', { text: opts.body }));
      if (opts.customNode) dlg.appendChild(opts.customNode);
      var actions = h('div', { 'class': 'dlg-actions' });
      opts.choices.forEach(function (c, i) {
        var cls = 'btn' + (c.kind === 'ghost' ? ' btn-ghost' : (c.kind === 'danger' ? ' btn-danger' : ''));
        actions.appendChild(h('button', {
          type: 'button', 'class': cls, text: c.label,
          autofocus: i === (opts.focus || 0),
          onclick: function () { result = c.value; dlg.close(); }
        }));
      });
      dlg.appendChild(actions);
      dlg.addEventListener('close', function () { dlg.remove(); resolve(result); });
      document.body.appendChild(dlg);
      dlg.showModal();
    });
  }
  function confirmDialog(title, body, confirmLabel, danger) {
    return choose({
      title: title, body: body, dismissValue: false, focus: 0,
      choices: [
        { label: 'Cancel', value: false, kind: 'ghost' },
        { label: confirmLabel, value: true, kind: danger ? 'danger' : 'primary' }
      ]
    });
  }

  function showQrModal() {
    var fullLink = BASE_ORIGIN + '/sub/' + currentSubToken;
    var svgMarkup = buildQrSvg(fullLink);
    var box = h('div', { 'class': 'qr-box' });
    if (svgMarkup) {
      box.innerHTML = svgMarkup;
    } else {
      box.textContent = 'Link is too long for inline QR.';
    }
    choose({
      title: 'Scan subscription link',
      body: 'Scan this QR code with your V2Ray / proxy client app to import your subscription immediately.',
      customNode: box,
      dismissValue: true,
      focus: 0,
      choices: [
        { label: 'Copy link', value: 'copy', kind: 'ghost' },
        { label: 'Done', value: 'done', kind: 'primary' }
      ]
    }).then(function (val) {
      if (val === 'copy') copySubLink();
    });
  }

  /* ---------- parsing (mirrors the server + smart Base64 decode) ---------- */
  function getScheme(line) {
    var m = String(line || '').trim().match(new RegExp('^([a-z][a-z0-9+.-]*)://', 'i'));
    return m ? m[1].toLowerCase() : '';
  }
  function isHttpLine(line) {
    var s = String(line || '').trim().toLowerCase();
    return s.indexOf('http://') === 0 || s.indexOf('https://') === 0;
  }
  function hasWs(s) {
    for (var i = 0; i < s.length; i++) if (s.charCodeAt(i) <= 32) return true;
    return false;
  }
  function isComment(l) { return l.indexOf('//') === 0 || l.indexOf(';') === 0 || l.indexOf('#') === 0; }

  function tryDecodeBase64Block(rawStr) {
    var s = String(rawStr || '').trim().replace(/\s+/g, '');
    if (s.length < 16 || SCHEME_RE.test(s) || !/^[A-Za-z0-9+/_=-]+$/.test(s)) return null;
    var norm = s.replace(/-/g, '+').replace(/_/g, '/');
    var pad = (4 - (norm.length % 4)) % 4;
    norm += '='.repeat(pad);
    try {
      var decoded = '';
      try { decoded = decodeURIComponent(escape(atob(norm))); } catch (e) { decoded = atob(norm); }
      var lines = decoded.split(NEWLINE).map(function (l) { return l.trim(); }).filter(function (l) { return SCHEME_RE.test(l) && !isHttpLine(l); });
      return lines.length > 0 ? lines : null;
    } catch (e) {
      return null;
    }
  }

  // Any "scheme://" starts a NEW entry. Returns entries plus how many lines were ignored.
  function analyze(text) {
    var raw = String(text || '').split(NEWLINE).map(function (l) { return l.trim(); }).filter(Boolean);
    var entries = [];
    var ignored = 0;
    raw.forEach(function (line) {
      if (SCHEME_RE.test(line)) entries.push(line);
      else if (entries.length > 0 && !hasWs(line) && !isComment(line)) entries[entries.length - 1] += line;
      else if (!isComment(line)) ignored++;
    });
    return { entries: entries, ignored: ignored };
  }
  function parseLines(text) { return analyze(text).entries; }
  function countDupes(list) { return list.length - new Set(list).size; }

  function isIPv6Config(line) {
    var s = String(line || '');
    var at = s.lastIndexOf('@');
    if (at === -1) return s.indexOf('[') !== -1 && s.indexOf(']') !== -1;
    var rest = s.slice(at + 1);
    var cut = rest.length;
    ['?', '/', '#'].forEach(function (c) { var i = rest.indexOf(c); if (i !== -1 && i < cut) cut = i; });
    return (rest.slice(0, cut).split(':').length - 1) >= 2;
  }

  function normalizeGroupKey(str) {
    return String(str || '').trim().split(' ').filter(Boolean).join('_');
  }

  function ensureGroupObj(entry) {
    if (Array.isArray(entry)) {
      var lines = entry.map(function (c) { return String(c || '').trim(); }).filter(Boolean);
      var subUrls = lines.filter(isHttpLine);
      var configs = lines.filter(function (l) { return !isHttpLine(l); });
      return { mode: (subUrls.length > 0 && configs.length === 0) ? 'sub' : 'configs', enabled: true, configs: configs, subUrls: subUrls, cachedSubConfigs: [], lastSynced: 0 };
    }
    if (entry && typeof entry === 'object') {
      return {
        mode: entry.mode === 'sub' ? 'sub' : 'configs',
        enabled: entry.enabled !== false,
        configs: Array.isArray(entry.configs) ? entry.configs : [],
        subUrls: Array.isArray(entry.subUrls) ? entry.subUrls : [],
        cachedSubConfigs: Array.isArray(entry.cachedSubConfigs) ? entry.cachedSubConfigs : [],
        lastSynced: Number(entry.lastSynced) > 0 ? Number(entry.lastSynced) : 0
      };
    }
    return { mode: 'configs', enabled: true, configs: [], subUrls: [], cachedSubConfigs: [], lastSynced: 0 };
  }

  /* ---------- subscription link card ---------- */
  function renderLink() {
    var shown = linkVisible ? currentSubToken : '\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022';
    $('subUrl').textContent = BASE_ORIGIN + '/sub/' + shown;
    $('openPlainBtn').href = BASE_ORIGIN + '/sub/' + currentSubToken + '?format=plain';
    $('toggleLinkBtn').textContent = linkVisible ? 'Hide' : 'Show';
    $('toggleLinkBtn').setAttribute('aria-pressed', linkVisible ? 'true' : 'false');
    $('legacyBanner').hidden = currentSubToken.length >= 16;
  }

  function copySubLink() {
    var text = BASE_ORIGIN + '/sub/' + currentSubToken;
    var btn = $('copySubBtn');
    function done() {
      btn.textContent = 'Copied!';
      showToast('Subscription link copied', 'ok');
      setTimeout(function () { btn.textContent = 'Copy link'; }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { showToast('Copy failed. Use Show and copy it manually.', 'err'); });
    } else {
      showToast('Copy is not supported here. Use Show and copy it manually.', 'err');
    }
  }

  async function postJson(url, body) {
    var res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    var data = {};
    try { data = await res.json(); } catch (e) {}
    if (res.status === 401) { window.location.reload(); }
    return { status: res.status, ok: res.ok, data: data };
  }

  async function regenerateSubToken() {
    var yes = await confirmDialog(
      'Create a new subscription link?',
      'Your current link stops working immediately. Every app or device using it will need the new link.',
      'Create new link', true
    );
    if (!yes) return;
    var btn = $('regenTokenBtn');
    btn.disabled = true;
    try {
      var r = await postJson('/regenerate-token');
      if (r.data && r.data.success && r.data.subToken) {
        currentSubToken = r.data.subToken;
        linkVisible = true;
        renderLink();
        showToast('New link ready. Copy it and update your apps.', 'ok');
      } else {
        showToast('Could not create a new link. Please try again.', 'err');
      }
    } catch (e) {
      showToast('Network error. Please try again.', 'err');
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------- settings ---------- */
  function setAutoSync(mode) {
    var clean = (mode === 'daily' || mode === 'weekly') ? mode : 'off';
    currentAutoSync = clean;
    updateAutoSyncUI();
    markDirty(true);
  }
  function updateAutoSyncUI() {
    document.querySelectorAll('.sync-opt').forEach(function (btn) {
      var active = btn.getAttribute('data-sync') === currentAutoSync;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    var hint = $('autoSyncHint');
    if (currentAutoSync === 'off') {
      hint.textContent = 'Scheduled sync is off. External links still sync automatically whenever your client app updates.';
    } else {
      var ago = formatAgo(lastAutoSyncTime);
      hint.textContent = 'Runs ' + currentAutoSync + ' in the background (add a Cron Trigger in Cloudflare Worker settings).' + (ago ? ' Last background run: ' + ago + '.' : '');
    }
  }

  function setRotationChunk(val) {
    var parsed = Math.max(1, Math.min(500, parseInt(val, 10) || 1));
    currentRotationChunk = parsed;
    var input = $('customChunkInput');
    if (parseInt(input.value, 10) !== parsed) input.value = parsed;
    updateAllCounts();
    markDirty(true);
  }
  function onCustomChunkInput(val) {
    var parsed = parseInt(val, 10);
    if (!isFinite(parsed) || parsed < 1) return;
    currentRotationChunk = Math.min(500, parsed);
    updateAllCounts();
    markDirty(true);
  }
  function updateChunkUI() {
    document.querySelectorAll('.preset').forEach(function (btn) {
      var active = parseInt(btn.getAttribute('data-chunk'), 10) === currentRotationChunk;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    $('divideHintText').textContent = 'Apps get ' + plural(currentRotationChunk, 'config') + ' from each active group in turn, then loop back until everything is listed.';
  }

  function togglePreview() {
    var btn = $('previewToggle');
    var open = btn.getAttribute('aria-expanded') !== 'true';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    $('previewBody').hidden = !open;
  }

  function toggleColorsDrawer() {
    var btn = $('colorsToggle');
    var open = btn.getAttribute('aria-expanded') !== 'true';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    $('colorsBody').hidden = !open;
  }

  /* ---------- dirty state ---------- */
  function markDirty(isDirty) {
    hasUnsavedChanges = isDirty;
    $('dirtyDot').classList.toggle('dirty', isDirty);
    var st = $('saveStatusText');
    st.textContent = isDirty ? 'Unsaved changes' : 'All changes saved';
    st.classList.toggle('dirty', isDirty);
    $('discardBtn').hidden = !isDirty;
    $('saveBar').classList.toggle('show', isDirty);
  }

  /* ---------- counts, chips, preview & search filter ---------- */
  function getGroupInfo(groupEl) {
    var mode = groupEl.dataset.mode === 'sub' ? 'sub' : 'configs';
    var enabled = groupEl.dataset.enabled !== 'false';
    var lastSynced = Number(groupEl._lastSynced) || 0;
    if (mode === 'sub') {
      var a = analyze(groupEl.querySelector('.sub-textarea').value);
      var urls = a.entries.filter(isHttpLine);
      var cached = Array.isArray(groupEl._cachedSubConfigs) ? groupEl._cachedSubConfigs : [];
      return {
        mode: 'sub', enabled: enabled, count: cached.length, subUrlCount: urls.length, lines: cached,
        ignored: (a.entries.length - urls.length) + a.ignored, dupes: countDupes(urls), lastSynced: lastSynced
      };
    }
    var b = analyze(groupEl.querySelector('.configs-textarea').value);
    return { mode: 'configs', enabled: enabled, count: b.entries.length, subUrlCount: 0, lines: b.entries, ignored: b.ignored, dupes: countDupes(b.entries), lastSynced: 0 };
  }

  function renderChips(container, lines) {
    container.innerHTML = '';
    if (!lines || lines.length === 0) return [];
    var counts = {};
    var v6 = 0;
    lines.forEach(function (l) {
      var s = getScheme(l) || 'other';
      counts[s] = (counts[s] || 0) + 1;
      if (isIPv6Config(l)) v6++;
    });
    var tags = Object.keys(counts);
    tags.forEach(function (s) {
      container.appendChild(h('span', { 'class': 'chip', text: s + ' ' + counts[s] }));
    });
    if (v6 > 0) {
      container.appendChild(h('span', { 'class': 'chip v6', text: 'ipv6 ' + v6 }));
      tags.push('ipv6');
    }
    return tags;
  }

  function renderPreview(groupInfos) {
    var box = $('batches');
    box.innerHTML = '';
    var chunk = currentRotationChunk;
    var batches = [];
    var offset = 0;
    var guard = 0;
    while (guard++ < 5000) {
      var added = false;
      for (var i = 0; i < groupInfos.length; i++) {
        var g = groupInfos[i];
        if (!g.enabled) continue;
        var n = Math.min(chunk, g.count - offset);
        if (n <= 0) continue;
        added = true;
        batches.push({ name: g.name, n: n, partial: n < chunk });
      }
      if (!added) break;
      offset += chunk;
    }
    var MAX = 60;
    batches.slice(0, MAX).forEach(function (b, idx) {
      if (idx > 0) box.appendChild(h('span', { 'class': 'batch-sep', text: '\\u2192', 'aria-hidden': 'true' }));
      var pill = h('span', { 'class': 'batch-pill' + (b.partial ? ' partial' : '') }, [
        display(b.name) + ' ', h('b', { text: '\\u00d7' + b.n })
      ]);
      if (b.partial) pill.title = 'Partial batch: this group has fewer than ' + chunk + ' configs left';
      box.appendChild(pill);
    });
    if (batches.length > MAX) box.appendChild(h('span', { 'class': 'batch-more', text: '\\u2026 +' + (batches.length - MAX) + ' more' }));
    if (batches.length === 0) box.appendChild(h('span', { 'class': 'batch-more', text: 'Nothing active to preview yet.' }));
    var partials = batches.filter(function (b) { return b.partial; }).length;
    $('previewSummary').textContent = plural(batches.length, 'batch', 'batches') + (partials ? ' \\u2022 ' + partials + ' partial' : '');
    return batches.length;
  }

  function applyGroupFilter() {
    var q = currentFilter.trim().toLowerCase();
    $('clearFilterBtn').hidden = !q;
    var groupEls = document.querySelectorAll('.server-group');
    var zones = document.querySelectorAll('.drop-zone');
    zones.forEach(function (z) { z.hidden = !!q; });
    groupEls.forEach(function (el) {
      if (!q) { el.hidden = false; return; }
      var hay = (el.dataset.searchHaystack || '').toLowerCase();
      el.hidden = hay.indexOf(q) === -1;
    });
  }

  function updateAllCounts() {
    updateChunkUI();
    var totalConfigs = 0;
    var activeGroupCount = 0;
    var groupEls = document.querySelectorAll('.server-group');
    var infos = [];

    groupEls.forEach(function (el) {
      var info = getGroupInfo(el);
      if (info.enabled) {
        totalConfigs += info.count;
        activeGroupCount += 1;
      }

      var titleInput = el.querySelector('.group-title');
      var cleanTitle = (titleInput && titleInput.value.trim()) ? titleInput.value.trim() : 'Group';
      var keyName = normalizeGroupKey(cleanTitle) || 'Group';
      infos.push({ name: keyName, count: info.count, enabled: info.enabled });
      var av = el.querySelector('.avatar');
      if (av) av.textContent = cleanTitle.charAt(0);

      var badge = el.querySelector('.badge');
      if (!info.enabled) {
        badge.textContent = 'Paused (' + plural(info.count, 'config') + ')';
        badge.className = 'badge paused';
      } else if (info.mode === 'sub') {
        if (info.subUrlCount === 0) { badge.textContent = 'No links yet'; badge.className = 'badge empty'; }
        else if (info.count > 0) { badge.textContent = plural(info.subUrlCount, 'link') + ' \\u2022 ' + plural(info.count, 'config'); badge.className = 'badge sub-mode'; }
        else { badge.textContent = plural(info.subUrlCount, 'link') + ' (not synced)'; badge.className = 'badge sub-mode'; }
      } else {
        badge.textContent = info.count === 0 ? 'Empty' : plural(info.count, 'config');
        badge.className = 'badge' + (info.count === 0 ? ' empty' : '');
      }

      var subStatus = el.querySelector('.sub-status-text');
      if (subStatus && !subStatus.dataset.busy) {
        var ago = formatAgo(info.lastSynced);
        if (info.count > 0) {
          subStatus.textContent = 'Synced ' + plural(info.count, 'config') + (ago ? ' \\u2022 ' + ago : '');
          subStatus.className = 'sub-status-text ok';
        } else {
          subStatus.textContent = 'Auto-syncs when client apps update';
          subStatus.className = 'sub-status-text';
        }
      }

      var chipTags = renderChips(el.querySelector('.chips'), info.lines);
      el.dataset.searchHaystack = cleanTitle + ' ' + info.mode + ' ' + chipTags.join(' ') + (info.enabled ? ' enabled active' : ' paused disabled');

      var dd = el.querySelector('.js-dedupe');
      dd.disabled = info.dupes === 0;
      dd.textContent = info.dupes > 0 ? 'Remove ' + plural(info.dupes, 'duplicate') : 'No duplicates';

      var warn = el.querySelector('.warn-text');
      if (info.ignored > 0) {
        warn.textContent = '\\u26A0 ' + plural(info.ignored, 'line') + ' not recognised and will be skipped';
        warn.hidden = false;
      } else {
        warn.textContent = '';
        warn.hidden = true;
      }

      el.querySelector('.group-prefix-code').textContent = cleanTitle + ' - <IP>';
      var rounds = info.enabled ? Math.ceil(info.count / currentRotationChunk) : 0;
      el.querySelector('.group-rounds-text').textContent = info.enabled
        ? (plural(rounds, 'batch', 'batches') + ' of up to ' + currentRotationChunk)
        : 'Skipped in output while paused';
    });

    var batchCount = renderPreview(infos) || 0;
    $('statConfigs').textContent = totalConfigs;
    $('statGroups').textContent = activeGroupCount;
    $('statBatches').textContent = batchCount;
    $('floatingTotalText').textContent = plural(totalConfigs, 'config') + ' in ' + plural(activeGroupCount, 'active group');

    var activeInfos = infos.filter(function (g) { return g.enabled; });
    if (activeInfos.length >= 2) {
      $('rotationExample').innerHTML = '';
      $('rotationExample').appendChild(document.createTextNode('Example: '));
      $('rotationExample').appendChild(h('b', { text: currentRotationChunk + ' from ' + display(activeInfos[0].name) }));
      $('rotationExample').appendChild(document.createTextNode(', then '));
      $('rotationExample').appendChild(h('b', { text: currentRotationChunk + ' from ' + display(activeInfos[1].name) }));
      $('rotationExample').appendChild(document.createTextNode(activeInfos.length > 2 ? ', and so on.' : ', then back to ' + display(activeInfos[0].name) + '.'));
    } else {
      $('rotationExample').textContent = 'Have at least two active groups to see how rotation interleaves them.';
    }

    applyGroupFilter();
  }

  /* ---------- read the screen back into state ---------- */
  function syncFromDOM() {
    var groupEls = document.querySelectorAll('.server-group');
    if (groupEls.length === 0) return;
    var ordered = {};
    groupEls.forEach(function (el, idx) {
      var prevName = el.dataset.originalName;
      var prevEntry = ensureGroupObj(dataGroups[prevName]);
      var titleInput = el.querySelector('.group-title');
      var rawName = (titleInput && titleInput.value.trim()) ? normalizeGroupKey(titleInput.value) : prevName;
      if (!rawName) rawName = 'Group_' + (idx + 1);
      var uniqueName = rawName;
      var suffix = 2;
      while (Object.prototype.hasOwnProperty.call(ordered, uniqueName)) { uniqueName = rawName + '_' + suffix; suffix++; }
      if (uniqueName !== prevName && collapsed.has(prevName)) { collapsed.delete(prevName); collapsed.add(uniqueName); }
      el.dataset.originalName = uniqueName;
      if (titleInput) titleInput.value = display(uniqueName);

      var mode = el.dataset.mode === 'sub' ? 'sub' : 'configs';
      var enabled = el.dataset.enabled !== 'false';
      var cfgArea = el.querySelector('.configs-textarea');
      var subArea = el.querySelector('.sub-textarea');
      ordered[uniqueName] = {
        mode: mode,
        enabled: enabled,
        configs: cfgArea ? parseLines(cfgArea.value) : prevEntry.configs,
        subUrls: subArea ? parseLines(subArea.value) : prevEntry.subUrls,
        cachedSubConfigs: Array.isArray(el._cachedSubConfigs) ? el._cachedSubConfigs : prevEntry.cachedSubConfigs,
        lastSynced: Number(el._lastSynced) || prevEntry.lastSynced || 0
      };
    });
    dataGroups = ordered;
  }

  function deduplicateGroup(groupDiv) {
    var mode = groupDiv.dataset.mode === 'sub' ? 'sub' : 'configs';
    var textarea = groupDiv.querySelector(mode === 'sub' ? '.sub-textarea' : '.configs-textarea');
    var lines = parseLines(textarea.value);
    var unique = Array.from(new Set(lines));
    var removed = lines.length - unique.length;
    if (removed === 0) return;
    textarea.value = unique.join(NEWLINE);
    updateAllCounts();
    markDirty(true);
    showToast('Removed ' + plural(removed, 'duplicate'), 'ok');
  }

  async function syncGroupSubLinks(groupDiv, statusEl, syncBtn) {
    var urls = parseLines(groupDiv.querySelector('.sub-textarea').value).filter(isHttpLine);
    if (urls.length === 0) {
      statusEl.textContent = 'Add at least one https:// link first.';
      statusEl.className = 'sub-status-text err';
      return;
    }
    syncBtn.disabled = true;
    syncBtn.textContent = 'Syncing\\u2026';
    statusEl.dataset.busy = '1';
    statusEl.textContent = 'Fetching configs\\u2026';
    statusEl.className = 'sub-status-text';
    try {
      var r = await postJson('/fetch-sub', { urls: urls });
      var data = r.data;
      delete statusEl.dataset.busy;
      if (data && Array.isArray(data.configs) && data.configs.length > 0) {
        groupDiv._cachedSubConfigs = data.configs;
        groupDiv._lastSynced = data.lastSynced || Date.now();
        syncFromDOM();
        updateAllCounts();
        markDirty(true);
        showToast('Synced ' + plural(data.configs.length, 'config'), 'ok');
      } else {
        statusEl.textContent = (data && data.errors && data.errors.length > 0) ? data.errors[0] : (data && data.error ? data.error : 'No valid configs returned');
        statusEl.className = 'sub-status-text err';
      }
    } catch (e) {
      delete statusEl.dataset.busy;
      statusEl.textContent = 'Could not reach that link.';
      statusEl.className = 'sub-status-text err';
    } finally {
      syncBtn.disabled = false;
      syncBtn.textContent = 'Sync now';
    }
  }

  async function syncAllGroupsFromToolbar() {
    syncFromDOM();
    var groupEls = Array.from(document.querySelectorAll('.server-group')).filter(function (el) {
      return el.dataset.mode === 'sub' && parseLines(el.querySelector('.sub-textarea').value).filter(isHttpLine).length > 0;
    });
    if (groupEls.length === 0) {
      showToast('No groups in Subscription link mode have links to sync.', 'err');
      return;
    }
    var btn = $('syncAllBtn');
    btn.disabled = true;
    btn.textContent = 'Syncing all\\u2026';
    try {
      await Promise.all(groupEls.map(function (el) {
        var st = el.querySelector('.sub-status-text');
        var sb = el.querySelector('.js-sync-sub');
        return syncGroupSubLinks(el, st, sb);
      }));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sync all links';
    }
  }

  /* ---------- drag and drop ---------- */
  function highlightZone(position) {
    if (dropPosition === position) return;
    dropPosition = position;
    document.querySelectorAll('.drop-zone').forEach(function (z) {
      z.classList.toggle('hover', parseInt(z.dataset.position, 10) === position);
    });
  }
  function updateDropTargetFromPoint(clientX, clientY) {
    if (dragFromIndex === null) return;
    var groups = document.querySelectorAll('.server-group');
    if (groups.length === 0) return;
    for (var i = 0; i < groups.length; i++) {
      var rect = groups[i].getBoundingClientRect();
      if (clientY >= rect.top - 16 && clientY <= rect.bottom + 16) {
        highlightZone((clientY - rect.top) < rect.height / 2 ? i : i + 1);
        return;
      }
    }
    var firstRect = groups[0].getBoundingClientRect();
    if (clientY < firstRect.top) { highlightZone(0); return; }
    var lastRect = groups[groups.length - 1].getBoundingClientRect();
    if (clientY > lastRect.bottom) highlightZone(groups.length);
  }
  function startDragAutoScrollLoop() {
    if (dragScrollRAF !== null) return;
    function step() {
      if (dragFromIndex === null) { dragScrollRAF = null; return; }
      var vh = window.innerHeight || document.documentElement.clientHeight;
      var TOP_ZONE = 150, BOTTOM_ZONE = 175, deltaY = 0;
      if (dragPointerY > 0 && dragPointerY < TOP_ZONE) {
        var a = Math.min(1, (TOP_ZONE - dragPointerY) / TOP_ZONE);
        deltaY = -Math.round(8 + a * a * 34);
      } else if (dragPointerY > vh - BOTTOM_ZONE) {
        var b = Math.min(1, (dragPointerY - (vh - BOTTOM_ZONE)) / BOTTOM_ZONE);
        deltaY = Math.round(8 + b * b * 34);
      }
      if (deltaY !== 0) { window.scrollBy(0, deltaY); updateDropTargetFromPoint(dragPointerX, dragPointerY); }
      dragScrollRAF = requestAnimationFrame(step);
    }
    dragScrollRAF = requestAnimationFrame(step);
  }
  function stopDragAutoScrollLoop() {
    if (dragScrollRAF !== null) { cancelAnimationFrame(dragScrollRAF); dragScrollRAF = null; }
  }
  function clearDragState() {
    dragFromIndex = null;
    dropPosition = null;
    stopDragAutoScrollLoop();
    document.body.classList.remove('is-dragging');
    document.querySelectorAll('.drop-zone.hover').forEach(function (z) { z.classList.remove('hover'); });
    document.querySelectorAll('.server-group.dragging').forEach(function (g) { g.classList.remove('dragging'); });
  }
  function commitDrop() {
    if (dragFromIndex === null || dropPosition === null) { clearDragState(); return; }
    var from = dragFromIndex, pos = dropPosition;
    clearDragState();
    moveGroupToPosition(from, pos);
  }
  function makeDropZone(position) {
    var zone = h('div', { 'class': 'drop-zone', 'data-position': String(position) });
    var insertBtn = h('button', { type: 'button', 'class': 'insert-btn', text: '+ Add group here', title: 'Insert a new group at this spot' });
    insertBtn.addEventListener('click', function (e) { e.stopPropagation(); addGroupAt(position); });
    zone.appendChild(insertBtn);
    zone.addEventListener('dragover', function (e) {
      if (dragFromIndex === null) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      highlightZone(position);
    });
    zone.addEventListener('drop', function (e) {
      if (dragFromIndex === null) return;
      e.preventDefault();
      e.stopPropagation();
      highlightZone(position);
      commitDrop();
    });
    return zone;
  }

  /* ---------- render groups ---------- */
  function renderGroups() {
    var container = $('groupsContainer');
    container.innerHTML = '';
    var names = Object.keys(dataGroups);

    if (names.length === 0) {
      container.appendChild(h('div', { 'class': 'empty-groups-state' }, [
        h('p', { text: 'No server groups yet. Create a group, then paste your configs or a subscription link into it.' }),
        h('button', { type: 'button', 'class': 'btn', text: '+ Add your first group', onclick: addNewGroup })
      ]));
      updateAllCounts();
      return;
    }

    container.appendChild(makeDropZone(0));

    names.forEach(function (groupName, index) {
      var entry = ensureGroupObj(dataGroups[groupName]);
      dataGroups[groupName] = entry;

      var groupDiv = h('div', {
        'class': 'server-group' + (collapsed.has(groupName) ? ' collapsed' : '') + (entry.enabled === false ? ' is-disabled' : ''),
        role: 'group', 'aria-label': display(groupName)
      });
      groupDiv.dataset.originalName = groupName;
      groupDiv.dataset.index = index;
      groupDiv.dataset.mode = entry.mode;
      groupDiv.dataset.enabled = entry.enabled === false ? 'false' : 'true';
      groupDiv._cachedSubConfigs = entry.cachedSubConfigs;
      groupDiv._lastSynced = entry.lastSynced || 0;

      /* header */
      var headerDiv = h('div', { 'class': 'group-header' });
      var leftDiv = h('div', { 'class': 'header-left' });

      var handle = h('span', { 'class': 'drag-handle', title: 'Drag to reorder', draggable: 'true', 'aria-hidden': 'true' }, [icon('grip', 18)]);
      handle.addEventListener('dragstart', function (e) {
        dragFromIndex = index;
        dropPosition = null;
        dragPointerX = e.clientX;
        dragPointerY = e.clientY;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', groupName);
        if (e.dataTransfer.setDragImage) e.dataTransfer.setDragImage(headerDiv, 24, 16);
        setTimeout(function () {
          if (dragFromIndex === null) return;
          document.body.classList.add('is-dragging');
          groupDiv.classList.add('dragging');
          startDragAutoScrollLoop();
        }, 0);
      });
      handle.addEventListener('dragend', clearDragState);

      var collapseBtn = h('button', {
        type: 'button', 'class': 'collapse-btn', title: 'Collapse or expand',
        'aria-label': 'Collapse or expand ' + display(groupName),
        'aria-expanded': collapsed.has(groupName) ? 'false' : 'true'
      }, [(function () { var c = icon('chev', 14); c.classList.add('chev'); return c; })()]);
      collapseBtn.addEventListener('click', function () {
        var nm = groupDiv.dataset.originalName;
        var isCollapsed = groupDiv.classList.toggle('collapsed');
        if (isCollapsed) collapsed.add(nm); else collapsed.delete(nm);
        collapseBtn.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
      });

      var avatar = h('span', { 'class': 'avatar', 'aria-hidden': 'true' });
      var titleInput = h('input', { type: 'text', 'class': 'group-title', maxlength: '60', 'aria-label': 'Group name', autocomplete: 'off' });
      titleInput.value = display(groupName);
      titleInput.addEventListener('input', function () { updateAllCounts(); markDirty(true); });
      titleInput.addEventListener('change', function () { updateGroupName(titleInput); });

      var countBadge = h('span', { 'class': 'badge' });
      leftDiv.appendChild(handle);
      leftDiv.appendChild(collapseBtn);
      leftDiv.appendChild(avatar);
      leftDiv.appendChild(titleInput);
      leftDiv.appendChild(countBadge);

      var rightDiv = h('div', { 'class': 'header-right' });

      var enableBtn = h('button', {
        type: 'button',
        'class': 'enable-btn' + (entry.enabled === false ? ' off' : ''),
        'aria-pressed': entry.enabled === false ? 'false' : 'true',
        title: 'Include or pause this group in subscription output'
      }, [
        h('span', { 'class': 'state-dot', 'aria-hidden': 'true' }),
        h('span', { 'class': 'enable-label', text: entry.enabled === false ? 'Paused' : 'Active' })
      ]);
      enableBtn.addEventListener('click', function () {
        var nextOn = groupDiv.dataset.enabled === 'false';
        groupDiv.dataset.enabled = nextOn ? 'true' : 'false';
        groupDiv.classList.toggle('is-disabled', !nextOn);
        enableBtn.classList.toggle('off', !nextOn);
        enableBtn.setAttribute('aria-pressed', nextOn ? 'true' : 'false');
        enableBtn.querySelector('.enable-label').textContent = nextOn ? 'Active' : 'Paused';
        syncFromDOM();
        updateAllCounts();
        markDirty(true);
      });

      var dedupBtn = h('button', { type: 'button', 'class': 'btn btn-ghost btn-sm js-dedupe', text: 'No duplicates', title: 'Remove repeated lines in this group' });
      dedupBtn.addEventListener('click', function () { deduplicateGroup(groupDiv); });
      var upBtn = h('button', { type: 'button', 'class': 'icon-btn', title: 'Move up', 'aria-label': 'Move ' + display(groupName) + ' up' }, [icon('up')]);
      upBtn.disabled = index === 0;
      upBtn.addEventListener('click', function () { moveGroup(index, -1); });
      var downBtn = h('button', { type: 'button', 'class': 'icon-btn', title: 'Move down', 'aria-label': 'Move ' + display(groupName) + ' down' }, [icon('down')]);
      downBtn.disabled = index === names.length - 1;
      downBtn.addEventListener('click', function () { moveGroup(index, 1); });
      var delBtn = h('button', { type: 'button', 'class': 'icon-btn danger', title: 'Delete group (you can undo)', 'aria-label': 'Delete ' + display(groupName) }, [icon('trash')]);
      delBtn.addEventListener('click', function () { deleteGroup(groupDiv.dataset.originalName); });
      [enableBtn, dedupBtn, upBtn, downBtn, delBtn].forEach(function (b) { rightDiv.appendChild(b); });

      headerDiv.appendChild(leftDiv);
      headerDiv.appendChild(rightDiv);

      /* body */
      var body = h('div', { 'class': 'group-body' });
      var chips = h('div', { 'class': 'chips' });

      var directModeBtn = h('button', { type: 'button', 'class': 'mode-btn' + (entry.mode === 'configs' ? ' active' : ''), text: 'Direct configs', 'aria-pressed': entry.mode === 'configs' ? 'true' : 'false' });
      var subModeBtn = h('button', { type: 'button', 'class': 'mode-btn' + (entry.mode === 'sub' ? ' active sub-active' : ''), text: 'Subscription link', 'aria-pressed': entry.mode === 'sub' ? 'true' : 'false' });
      var switchGroup = h('div', { 'class': 'mode-switch-group', role: 'group', 'aria-label': 'Source type' }, [directModeBtn, subModeBtn]);

      var subStatus = h('span', { 'class': 'sub-status-text' });
      var syncSubBtn = h('button', { type: 'button', 'class': 'btn btn-ghost btn-sm js-sync-sub', text: 'Sync now' });
      syncSubBtn.addEventListener('click', function () { syncGroupSubLinks(groupDiv, subStatus, syncSubBtn); });
      var subRight = h('div', { 'class': 'sub-actions-right' }, [subStatus, syncSubBtn]);
      subRight.hidden = entry.mode !== 'sub';

      var modeBar = h('div', { 'class': 'mode-bar' }, [switchGroup, subRight]);

      var cfgArea = h('textarea', { 'class': 'configs-textarea', spellcheck: 'false', placeholder: 'Paste configs here, one per line (or paste a Base64 subscription payload to auto-decode)\\u2026', 'aria-label': 'Configs for ' + display(groupName) });
      cfgArea.value = entry.configs.join(NEWLINE);
      cfgArea.hidden = entry.mode !== 'configs';

      var subArea = h('textarea', { 'class': 'sub-textarea', spellcheck: 'false', placeholder: 'Paste subscription link(s), one per line (https://\\u2026)', 'aria-label': 'Subscription links for ' + display(groupName) });
      subArea.value = entry.subUrls.join(NEWLINE);
      subArea.hidden = entry.mode !== 'sub';

      function setMode(mode) {
        if (groupDiv.dataset.mode === mode) return;
        groupDiv.dataset.mode = mode;
        var isSub = mode === 'sub';
        directModeBtn.className = 'mode-btn' + (isSub ? '' : ' active');
        subModeBtn.className = 'mode-btn' + (isSub ? ' active sub-active' : '');
        directModeBtn.setAttribute('aria-pressed', isSub ? 'false' : 'true');
        subModeBtn.setAttribute('aria-pressed', isSub ? 'true' : 'false');
        cfgArea.hidden = isSub;
        subArea.hidden = !isSub;
        subRight.hidden = !isSub;
        syncFromDOM();
        updateAllCounts();
        markDirty(true);
      }

      // Smart paste & input handling on Direct Configs
      cfgArea.addEventListener('input', function () {
        var rawLines = String(cfgArea.value || '').split(NEWLINE).map(function (l) { return l.trim(); }).filter(Boolean);
        var changed = false;
        var expanded = [];
        var decodedCount = 0;
        rawLines.forEach(function (l) {
          var dec = tryDecodeBase64Block(l);
          if (dec && dec.length > 0) {
            changed = true;
            decodedCount += dec.length;
            dec.forEach(function (d) { expanded.push(d); });
          } else {
            expanded.push(l);
          }
        });
        if (changed) {
          cfgArea.value = expanded.join(NEWLINE);
          showToast('Auto-decoded ' + plural(decodedCount, 'config') + ' from Base64', 'ok');
        } else if (rawLines.length > 0 && rawLines.every(isHttpLine)) {
          showToast('Looks like a subscription URL.', '', {
            actionLabel: 'Switch to Subscription link',
            duration: 6000,
            onAction: function () {
              subArea.value = rawLines.join(NEWLINE);
              cfgArea.value = '';
              setMode('sub');
              syncGroupSubLinks(groupDiv, subStatus, syncSubBtn);
            }
          });
        }
        updateAllCounts();
        markDirty(true);
      });

      subArea.addEventListener('input', function () { updateAllCounts(); markDirty(true); });

      directModeBtn.addEventListener('click', function () { setMode('configs'); });
      subModeBtn.addEventListener('click', function () { setMode('sub'); });

      var footerDiv = h('div', { 'class': 'group-footer' });
      var prefixCode = h('code', { 'class': 'group-prefix-code' });
      var left = h('span', null, [document.createTextNode('Name shown in apps: '), prefixCode]);
      var warn = h('span', { 'class': 'warn-text', hidden: true, role: 'status' });
      var rounds = h('span', { 'class': 'group-rounds-text' });
      footerDiv.appendChild(left);
      footerDiv.appendChild(warn);
      footerDiv.appendChild(rounds);

      groupDiv.addEventListener('dragover', function (e) {
        if (dragFromIndex === null) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        var rect = groupDiv.getBoundingClientRect();
        highlightZone((e.clientY - rect.top) < rect.height / 2 ? index : index + 1);
      });
      groupDiv.addEventListener('drop', function (e) {
        if (dragFromIndex === null) return;
        e.preventDefault();
        e.stopPropagation();
        commitDrop();
      });

      [chips, modeBar, cfgArea, subArea, footerDiv].forEach(function (n) { body.appendChild(n); });
      groupDiv.appendChild(headerDiv);
      groupDiv.appendChild(body);
      container.appendChild(groupDiv);
      container.appendChild(makeDropZone(index + 1));
    });

    updateAllCounts();
  }

  /* ---------- group operations ---------- */
  function moveGroup(index, direction) {
    var total = Object.keys(dataGroups).length;
    var target = index + direction;
    if (target < 0 || target >= total) return;
    moveGroupToPosition(index, direction === 1 ? target + 1 : target);
  }

  function moveGroupToPosition(from, position) {
    syncFromDOM();
    var names = Object.keys(dataGroups);
    if (from < 0 || from >= names.length) return;
    if (position < 0 || position > names.length) return;
    if (position === from || position === from + 1) { renderGroups(); return; }
    var moved = names.splice(from, 1)[0];
    names.splice(position > from ? position - 1 : position, 0, moved);
    var reordered = {};
    names.forEach(function (n) { reordered[n] = dataGroups[n]; });
    dataGroups = reordered;
    markDirty(true);
    renderGroups();
  }

  function updateGroupName(inputElement) {
    var groupDiv = inputElement.closest('.server-group');
    var oldName = groupDiv.dataset.originalName;
    var newName = normalizeGroupKey(inputElement.value);
    if (!newName) {
      inputElement.value = display(oldName);
      updateAllCounts();
      return;
    }
    if (oldName !== newName) {
      if (Object.prototype.hasOwnProperty.call(dataGroups, newName)) {
        showToast('A group named "' + display(newName) + '" already exists.', 'err');
        inputElement.value = display(oldName);
        updateAllCounts();
        return;
      }
      var rebuilt = {};
      Object.keys(dataGroups).forEach(function (key) {
        if (key === oldName) rebuilt[newName] = dataGroups[oldName]; else rebuilt[key] = dataGroups[key];
      });
      dataGroups = rebuilt;
      if (collapsed.has(oldName)) { collapsed.delete(oldName); collapsed.add(newName); }
      groupDiv.dataset.originalName = newName;
      updateAllCounts();
      markDirty(true);
    }
  }

  function insertGroupAt(name, entry, index) {
    var names = Object.keys(dataGroups);
    var unique = name, n = 2;
    while (Object.prototype.hasOwnProperty.call(dataGroups, unique)) { unique = name + '_' + n; n++; }
    names.splice(Math.min(index, names.length), 0, unique);
    var rebuilt = {};
    names.forEach(function (k) { rebuilt[k] = k === unique ? entry : dataGroups[k]; });
    dataGroups = rebuilt;
  }

  function addGroupAt(position) {
    syncFromDOM();
    var uniqueId = 'New_Group_' + Math.floor(1000 + Math.random() * 9000);
    insertGroupAt(uniqueId, { mode: 'configs', enabled: true, configs: [], subUrls: [], cachedSubConfigs: [], lastSynced: 0 }, position);
    markDirty(true);
    renderGroups();
    var els = document.querySelectorAll('.server-group');
    var target = els[Math.min(position, els.length - 1)];
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      var t = target.querySelector('.group-title');
      if (t) { t.focus(); t.select(); }
    }
  }

  function addNewGroup() {
    syncFromDOM();
    var uniqueId = 'New_Group_' + Math.floor(1000 + Math.random() * 9000);
    dataGroups[uniqueId] = { mode: 'configs', enabled: true, configs: [], subUrls: [], cachedSubConfigs: [], lastSynced: 0 };
    markDirty(true);
    renderGroups();
    var els = document.querySelectorAll('.server-group');
    var last = els[els.length - 1];
    if (last) {
      last.scrollIntoView({ behavior: 'smooth', block: 'center' });
      var t = last.querySelector('.group-title');
      if (t) { t.focus(); t.select(); }
    }
  }

  function deleteGroup(groupName) {
    syncFromDOM();
    var idx = Object.keys(dataGroups).indexOf(groupName);
    if (idx === -1) return;
    var removed = dataGroups[groupName];
    delete dataGroups[groupName];
    collapsed.delete(groupName);
    markDirty(true);
    renderGroups();
    showToast('Deleted "' + display(groupName) + '"', '', {
      actionLabel: 'Undo', duration: 9000,
      onAction: function () {
        syncFromDOM();
        insertGroupAt(groupName, removed, idx);
        markDirty(true);
        renderGroups();
      }
    });
  }

  function setAllCollapsed(flag) {
    syncFromDOM();
    collapsed = new Set(flag ? Object.keys(dataGroups) : []);
    document.querySelectorAll('.server-group').forEach(function (el) {
      el.classList.toggle('collapsed', flag);
      var b = el.querySelector('.collapse-btn');
      if (b) b.setAttribute('aria-expanded', flag ? 'false' : 'true');
    });
  }

  /* ---------- saving ---------- */
  function hasAnyContent() {
    return Object.keys(dataGroups).some(function (k) {
      var e = ensureGroupObj(dataGroups[k]);
      return e.configs.length > 0 || e.subUrls.length > 0 || e.cachedSubConfigs.length > 0;
    });
  }

  async function saveAll(force) {
    if (saving) return;
    syncFromDOM();
    if (!hasAnyContent()) {
      var go = await choose({
        title: 'Save an empty subscription?',
        body: 'None of your groups contain configs or links, so apps will receive an empty list.',
        dismissValue: false, focus: 0,
        choices: [{ label: 'Keep editing', value: false, kind: 'ghost' }, { label: 'Save anyway', value: true, kind: 'danger' }]
      });
      if (!go) return;
    }
    saving = true;
    var saveBtn = $('saveAllBtn');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving\\u2026';
    try {
      var r = await postJson('/save', {
        groups: dataGroups, rotationChunk: currentRotationChunk, subTitle: currentSubTitle,
        autoSync: currentAutoSync, rev: currentRev, force: force === true
      });
      if (r.data && r.data.success) {
        if (r.data.groups && typeof r.data.groups === 'object') dataGroups = r.data.groups;
        if (r.data.rev) currentRev = r.data.rev;
        markDirty(false);
        renderGroups();
        showToast('Saved', 'ok');
      } else if (r.status === 409) {
        var choice = await choose({
          title: 'Changed somewhere else',
          body: 'Another tab or device saved changes after you opened this page. You can overwrite them with your version, or reload to see theirs (your unsaved edits will be lost).',
          dismissValue: 'cancel', focus: 2,
          choices: [
            { label: 'Overwrite', value: 'overwrite', kind: 'danger' },
            { label: 'Reload latest', value: 'reload', kind: 'ghost' },
            { label: 'Keep editing', value: 'cancel', kind: 'ghost' }
          ]
        });
        if (choice === 'reload') { hasUnsavedChanges = false; window.location.reload(); }
        else if (choice === 'overwrite') { saving = false; saveBtn.disabled = false; saveBtn.innerHTML = SAVE_LABEL; return saveAll(true); }
      } else {
        showToast('Could not save: ' + ((r.data && r.data.error) || 'unknown error'), 'err');
      }
    } catch (e) {
      showToast('Network error while saving. Your edits are still here.', 'err');
    } finally {
      saving = false;
      saveBtn.disabled = false;
      saveBtn.innerHTML = SAVE_LABEL;
    }
  }

  async function discardChanges() {
    var yes = await confirmDialog('Discard unsaved changes?', 'Everything you changed since the last save will be lost.', 'Discard changes', true);
    if (!yes) return;
    hasUnsavedChanges = false;
    window.location.reload();
  }

  async function signOut() {
    if (hasUnsavedChanges) {
      var yes = await confirmDialog('Sign out with unsaved changes?', 'You have changes that have not been saved yet. They will be lost.', 'Sign out anyway', true);
      if (!yes) return;
    }
    try { await postJson('/logout'); } catch (e) {}
    hasUnsavedChanges = false;
    window.location.reload();
  }

  /* ---------- wiring ---------- */
  $('addGroupTop').addEventListener('click', addNewGroup);
  $('addGroupList').addEventListener('click', addNewGroup);
  $('syncAllBtn').addEventListener('click', syncAllGroupsFromToolbar);
  $('collapseAllBtn').addEventListener('click', function () { setAllCollapsed(true); });
  $('expandAllBtn').addEventListener('click', function () { setAllCollapsed(false); });
  $('copySubBtn').addEventListener('click', copySubLink);
  $('qrSubBtn').addEventListener('click', showQrModal);
  $('regenTokenBtn').addEventListener('click', regenerateSubToken);
  $('upgradeLinkBtn').addEventListener('click', regenerateSubToken);
  $('toggleLinkBtn').addEventListener('click', function () { linkVisible = !linkVisible; renderLink(); });
  $('previewToggle').addEventListener('click', togglePreview);
  $('colorsToggle').addEventListener('click', toggleColorsDrawer);
  $('saveAllBtn').addEventListener('click', function () { saveAll(false); });
  $('discardBtn').addEventListener('click', discardChanges);
  $('signOutBtn').addEventListener('click', signOut);
  $('subTitleInput').addEventListener('input', function (e) { currentSubTitle = String(e.target.value || ''); markDirty(true); });
  $('customChunkInput').addEventListener('input', function (e) { onCustomChunkInput(e.target.value); });

  $('groupFilterInput').addEventListener('input', function (e) {
    currentFilter = String(e.target.value || '');
    applyGroupFilter();
  });
  $('clearFilterBtn').addEventListener('click', function () {
    currentFilter = '';
    $('groupFilterInput').value = '';
    applyGroupFilter();
    $('groupFilterInput').focus();
  });

  document.querySelectorAll('.preset').forEach(function (b) {
    b.addEventListener('click', function () { setRotationChunk(b.getAttribute('data-chunk')); });
  });
  document.querySelectorAll('.sync-opt').forEach(function (b) {
    b.addEventListener('click', function () { setAutoSync(b.getAttribute('data-sync')); });
  });

  var groupsContainerEl = $('groupsContainer');
  groupsContainerEl.addEventListener('dragover', function (e) {
    if (dragFromIndex === null) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  });
  groupsContainerEl.addEventListener('drop', function (e) {
    if (dragFromIndex === null) return;
    e.preventDefault();
    commitDrop();
  });
  window.addEventListener('dragover', function (e) {
    if (dragFromIndex === null) return;
    dragPointerX = e.clientX;
    dragPointerY = e.clientY;
    e.preventDefault();
  }, true);
  document.addEventListener('dragend', clearDragState);
  window.addEventListener('drop', function (e) { if (dragFromIndex !== null) e.preventDefault(); });

  window.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      saveAll(false);
    }
  });
  window.addEventListener('beforeunload', function (e) {
    if (hasUnsavedChanges) { e.preventDefault(); e.returnValue = ''; }
  });

  /* ---------- start ---------- */
  $('previewChev').appendChild(icon('chev', 14));
  $('colorsChev').appendChild(icon('chev', 14));
  $('subTitleInput').value = currentSubTitle;
  $('customChunkInput').value = currentRotationChunk;
  $('saveAllBtn').innerHTML = SAVE_LABEL;
  initColors();
  renderLink();
  updateAutoSyncUI();
  updateChunkUI();
  renderGroups();
})();
</script>
</body>
</html>`;
}
