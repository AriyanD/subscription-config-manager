const DASHBOARD_PASSWORD = "CHANGE_ME_TO_YOUR_OWN_PASSWORD";

// Default number of configs to take from each group per rotation round (can be changed in the UI)
const DEFAULT_ROTATION_CHUNK = 3;

// Default subscription name shown by apps (editable from the dashboard)
const DEFAULT_SUB_TITLE = 'Subscription Hub';

// Initial entries if the database is empty
const defaultGroups = {
  "Germany_Server": {
    mode: "configs",
    configs: [
      "example://sample-1@192.0.2.1:443"
    ],
    subUrls: [],
    cachedSubConfigs: []
  }
};

// Any "scheme://" at the start of a line begins a NEW entry (this is what keeps entries from being glued together)
const SCHEME_LINE_RE = /^[a-z][a-z0-9+.\-]*:\/\//i;

// User-Agent sent when fetching remote subscription links.
// Optional: add a text variable named SUB_FETCH_UA in the Worker settings to override it.
const FETCH_UA = (typeof SUB_FETCH_UA !== 'undefined' && SUB_FETCH_UA) ? String(SUB_FETCH_UA) : 'SubHub/1.0';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

/* ------------------------------------------------------------------ */
/* Auth helpers                                                        */
/* ------------------------------------------------------------------ */

async function getAuthToken() {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('sub-hub:' + DASHBOARD_PASSWORD));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
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

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ------------------------------------------------------------------ */
/* Request handler                                                     */
/* ------------------------------------------------------------------ */

async function handleRequest(request) {
  const url = new URL(request.url);
  const subToken = await envFetchOrCreateSubToken();
  const isProtectedSubMatch =
    url.pathname === `/sub/${subToken}` ||
    url.pathname === `/sub-${subToken}` ||
    (url.pathname === '/sub' && url.searchParams.get('key') === subToken) ||
    url.searchParams.get('raw') === subToken;

  // 1. ONLY ALLOW THE CLIENT APP TO FETCH THE LIST WITH THE SECRET 6-DIGIT SUBSCRIPTION CODE
  if (isProtectedSubMatch) {
    let serverGroups = await envFetchGroups();
    let rotationChunk = await envFetchRotationChunk();

    const subTitle = await envFetchSubTitle();

    // Optional query override e.g. /sub/123456?chunk=5
    if (url.searchParams.has('chunk')) {
      const qChunk = parseInt(url.searchParams.get('chunk'), 10);
      if (Number.isFinite(qChunk) && qChunk >= 1) {
        rotationChunk = qChunk;
      }
    }

    // Resolve each group's active configs (direct configs OR live-fetched subscription URLs)
    const groupNames = Object.keys(serverGroups);
    const cleaned = {};
    let kvCacheUpdated = false;

    await Promise.all(groupNames.map(async (g) => {
      const entry = normalizeGroupEntry(serverGroups[g]);
      if (entry.mode === 'sub') {
        if (entry.subUrls.length > 0) {
          const fetchResult = await fetchAndDecodeSubUrls(entry.subUrls);
          if (fetchResult.configs.length > 0) {
            cleaned[g] = fetchResult.configs;
            if (JSON.stringify(entry.cachedSubConfigs) !== JSON.stringify(fetchResult.configs)) {
              entry.cachedSubConfigs = fetchResult.configs;
              serverGroups[g] = entry;
              kvCacheUpdated = true;
            }
          } else {
            // Fallback to cached configs if remote subscription server is temporarily unreachable
            cleaned[g] = Array.isArray(entry.cachedSubConfigs) ? entry.cachedSubConfigs.filter(c => typeof c === 'string' && c.trim() !== '') : [];
          }
        } else {
          cleaned[g] = [];
        }
      } else {
        // Direct configs mode (also resolves any http/https subscription URL if pasted directly)
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

    if (kvCacheUpdated) {
      try {
        await STORE.put("server_groups", JSON.stringify(serverGroups));
      } catch (e) {}
    }

    // Round-robin: take rotationChunk configs from group 1, then group 2, ...
    // then loop back for the next rotationChunk from each, until all are used.
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
        slice.forEach(config => {
          allConfigs.push(renameConfigWithIP(config, cleanGroupName));
        });
      }
      if (!addedAny) break;
      offset += rotationChunk;
    }

    const subscriptionContent = allConfigs.join('\n');
    // Use ?format=plain if you ever want to inspect unencoded output in browser
    const outputBody = url.searchParams.get('format') === 'plain'
      ? subscriptionContent
      : btoa(unescape(encodeURIComponent(subscriptionContent)));

    return new Response(outputBody, {
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Access-Control-Allow-Origin': '*',
        'Profile-Title': 'base64:' + btoa(unescape(encodeURIComponent(subTitle))),
        'Profile-Update-Interval': '12'
      },
    });
  }

  // Block bare /sub or wrong /sub/... tokens so scanners cannot guess or scrape the link
  if (url.pathname === '/sub' || url.pathname.startsWith('/sub/') || url.pathname.startsWith('/sub-')) {
    return new Response('404 Not Found', {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' }
    });
  }

  // 2. CHECK LOGIN COOKIE FOR WEB DASHBOARD ACCESS
  const authToken = await getAuthToken();
  const isLoggedIn = safeEqual(getCookie(request.headers.get('Cookie'), 'auth_token'), authToken);

  // Handle Login Request Verification
  if (request.method === 'POST' && url.pathname === '/login') {
    try {
      const data = await request.json();
      if (typeof data.password === 'string' && safeEqual(data.password, DASHBOARD_PASSWORD)) {
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'content-type': 'application/json',
            'Set-Cookie': `auth_token=${authToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000` // 30 Days
          }
        });
      }
      return new Response(JSON.stringify({ success: false, error: "Incorrect Password" }), { status: 403, headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // If not logged in, force show the Login Page layout
  if (!isLoggedIn) {
    return new Response(getLoginPageHTML(), {
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }

  // 3. SECURE ENDPOINTS (Only active if logged in via cookie verification)
  if (request.method === 'POST' && url.pathname === '/fetch-sub') {
    try {
      const body = await request.json();
      const rawUrls = Array.isArray(body.urls) ? body.urls : (typeof body.url === 'string' ? [body.url] : []);
      const validUrls = rawUrls.map(u => String(u || '').trim()).filter(u => isHttpUrl(u));
      if (validUrls.length === 0) {
        return new Response(JSON.stringify({
          success: false,
          error: "Please enter at least one valid http:// or https:// subscription link.",
          configs: [],
          count: 0
        }), { status: 400, headers: { 'content-type': 'application/json' } });
      }
      const result = await fetchAndDecodeSubUrls(validUrls);
      return new Response(JSON.stringify({
        success: result.configs.length > 0 || result.errors.length === 0,
        configs: result.configs,
        count: result.configs.length,
        errors: result.errors
      }), { headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message, configs: [], count: 0 }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  if (request.method === 'POST' && url.pathname === '/save') {
    try {
      const data = await request.json();
      if (data && data.groups && typeof data.groups === 'object') {
        const normalizedGroups = {};
        const groupKeys = Object.keys(data.groups);
        await Promise.all(groupKeys.map(async (k) => {
          const entry = normalizeGroupEntry(data.groups[k]);
          if (entry.mode === 'sub' && entry.subUrls.length > 0) {
            const res = await fetchAndDecodeSubUrls(entry.subUrls);
            if (res.configs.length > 0) {
              entry.cachedSubConfigs = res.configs;
            }
          }
          normalizedGroups[k] = entry;
        }));
        // Keep the order the user arranged in the UI
        const orderedGroups = {};
        groupKeys.forEach(k => { orderedGroups[k] = normalizedGroups[k]; });
        await STORE.put("server_groups", JSON.stringify(orderedGroups));
      }
      if (data && data.rotationChunk !== undefined) {
        const parsedChunk = Math.max(1, parseInt(data.rotationChunk, 10) || DEFAULT_ROTATION_CHUNK);
        await STORE.put("rotation_chunk", String(parsedChunk));
      }
      if (data && typeof data.subToken === 'string' && /^\d{6}$/.test(data.subToken)) {
        await STORE.put("sub_token", data.subToken);
      }
      if (data && typeof data.subTitle === 'string') {
        const cleanTitle = data.subTitle.trim().slice(0, 100) || DEFAULT_SUB_TITLE;
        await STORE.put("sub_title", cleanTitle);
      }
      const latestGroups = await envFetchGroups();
      return new Response(JSON.stringify({ success: true, groups: latestGroups }), { headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // Regenerate a new random 6-digit subscription token on demand
  if (request.method === 'POST' && url.pathname === '/regenerate-token') {
    try {
      const newToken = generateSixDigitCode();
      await STORE.put("sub_token", newToken);
      return new Response(JSON.stringify({ success: true, subToken: newToken }), {
        headers: { 'content-type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // If logged in, safely render Graphic Interface Panel
  let serverGroups = await envFetchGroups();
  let rotationChunk = await envFetchRotationChunk();
  const adminTitle = await envFetchSubTitle();
  return new Response(getAdminPanelHTML(url.origin, serverGroups, rotationChunk, subToken, adminTitle), {
    headers: { 'content-type': 'text/html; charset=utf-8' }
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

// Any "scheme://" line that is not a plain web link counts as an entry
function isEntryLine(str) {
  const s = String(str || '').trim();
  return SCHEME_LINE_RE.test(s) && !isHttpUrl(s);
}

// Splits text into entries. A line that starts with ANY "scheme://" is always a new entry,
// so an unrecognised scheme can never be glued onto the previous entry.
// Only lines that look like a wrapped continuation (no scheme, no whitespace) are stitched.
function splitNonEmptyLines(text) {
  const rawLines = String(text || '')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean);

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
      // Stitch wrapped continuation lines (common with long IPv6 URLs)
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
  if (directLines.length > 0) {
    return directLines;
  }

  try {
    const decoded = safeBase64Decode(trimmed);
    const decodedLines = splitNonEmptyLines(decoded).filter(l => isEntryLine(l));
    if (decodedLines.length > 0) {
      return decodedLines;
    }
  } catch (e) {}

  return directLines;
}

async function fetchAndDecodeSubUrls(urls) {
  const errors = [];
  const perUrlConfigs = await Promise.all((urls || []).map(async (targetUrl) => {
    const cleanUrl = String(targetUrl || '').trim();
    if (!isHttpUrl(cleanUrl)) return [];
    try {
      const res = await fetch(cleanUrl, {
        method: 'GET',
        headers: {
          'User-Agent': FETCH_UA,
          'Accept': '*/*'
        }
      });
      if (!res.ok) {
        errors.push(`${cleanUrl}: HTTP ${res.status}`);
        return [];
      }
      const text = await res.text();
      const decoded = decodeSubscriptionPayload(text);
      if (decoded.length === 0) {
        errors.push(`${cleanUrl}: No valid configs found`);
        return [];
      }
      return decoded;
    } catch (err) {
      errors.push(`${cleanUrl}: ${err && err.message ? err.message : 'Fetch error'}`);
      return [];
    }
  }));
  const allConfigs = [];
  perUrlConfigs.forEach(list => {
    list.forEach(c => allConfigs.push(c));
  });
  return { configs: allConfigs, errors };
}

function normalizeGroupEntry(rawEntry) {
  if (Array.isArray(rawEntry)) {
    const cleaned = splitNonEmptyLines(rawEntry.join('\n'));
    const subUrls = cleaned.filter(c => isHttpUrl(c));
    const configs = cleaned.filter(c => !isHttpUrl(c));
    const mode = (subUrls.length > 0 && configs.length === 0) ? 'sub' : 'configs';
    return {
      mode,
      configs,
      subUrls,
      cachedSubConfigs: []
    };
  }
  if (rawEntry && typeof rawEntry === 'object') {
    const mode = rawEntry.mode === 'sub' ? 'sub' : 'configs';
    const configs = Array.isArray(rawEntry.configs)
      ? splitNonEmptyLines(rawEntry.configs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    const subUrls = Array.isArray(rawEntry.subUrls)
      ? rawEntry.subUrls.map(c => String(c || '').trim()).filter(c => isHttpUrl(c))
      : [];
    const cachedSubConfigs = Array.isArray(rawEntry.cachedSubConfigs)
      ? splitNonEmptyLines(rawEntry.cachedSubConfigs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    return { mode, configs, subUrls, cachedSubConfigs };
  }
  return { mode: 'configs', configs: [], subUrls: [], cachedSubConfigs: [] };
}

function normalizeAllGroups(rawGroups) {
  const source = (rawGroups && typeof rawGroups === 'object' && !Array.isArray(rawGroups) && Object.keys(rawGroups).length > 0)
    ? rawGroups
    : defaultGroups;
  const out = {};
  Object.keys(source).forEach(k => {
    out[k] = normalizeGroupEntry(source[k]);
  });
  return out;
}

function generateSixDigitCode() {
  try {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return String(100000 + (arr[0] % 900000));
  } catch (e) {
    return String(Math.floor(100000 + Math.random() * 900000));
  }
}

async function envFetchOrCreateSubToken() {
  try {
    const existing = await STORE.get("sub_token");
    if (existing && /^\d{6}$/.test(existing.trim())) {
      return existing.trim();
    }
    const generated = generateSixDigitCode();
    await STORE.put("sub_token", generated);
    return generated;
  } catch (e) {
    return "482915";
  }
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
// Returns { host, port } where port may be ''.
function splitHostPort(hostPort) {
  const hp = String(hostPort || '').trim();

  const bracket = hp.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) return { host: bracket[1], port: bracket[2] || '' };

  const colonCount = (hp.match(/:/g) || []).length;
  if (colonCount <= 1) {
    const m = hp.match(/^([^:/?#]+)(?::(\d+))?$/);
    return m ? { host: m[1], port: m[2] || '' } : { host: hp, port: '' };
  }

  // 2+ colons => unbracketed IPv6
  const idx = hp.lastIndexOf(':');
  const candidateHost = hp.slice(0, idx);
  const candidatePort = hp.slice(idx + 1);
  if (/^\d{1,5}$/.test(candidatePort) && Number(candidatePort) <= 65535 && isValidIPv6(candidateHost)) {
    return { host: candidateHost, port: candidatePort };
  }
  if (isValidIPv6(hp)) return { host: hp, port: '' };
  return { host: hp, port: '' };
}

// Parses out the host, normalises unbracketed IPv6 so clients don't drop it,
// and injects the custom group name as the entry label.
// Scheme-agnostic: handles URL-style entries (user@host:port?...), encoded-JSON bodies,
// and legacy encoded "user:secret@host:port" bodies.
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

    // Encoded JSON body (no "@" anywhere): set the label field inside the JSON itself
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
      // Legacy form: the whole authority is encoded ("user:secret@host:port")
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

async function envFetchGroups() {
  try {
    const kvData = await STORE.get("server_groups");
    if (kvData) {
      const parsed = JSON.parse(kvData);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length > 0) {
        return normalizeAllGroups(parsed);
      }
    }
  } catch (e) {}
  return normalizeAllGroups(defaultGroups);
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

/* ------------------------------------------------------------------ */
/* LOGIN SCREEN                                                        */
/* ------------------------------------------------------------------ */

function getLoginPageHTML() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <title>Sign in · Subscription Hub</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            background:
                radial-gradient(900px 500px at 15% -10%, rgba(99,102,241,0.22), transparent 60%),
                radial-gradient(800px 500px at 100% 110%, rgba(14,165,233,0.18), transparent 60%),
                #0b0c10;
            color: #e5e7eb;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; padding: 20px;
        }
        .card {
            width: 100%; max-width: 380px; padding: 34px 30px 30px;
            background: rgba(22,23,29,0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            backdrop-filter: blur(14px);
            box-shadow: 0 24px 60px rgba(0,0,0,0.45);
            text-align: center;
        }
        .logo {
            width: 54px; height: 54px; margin: 0 auto 18px; border-radius: 16px;
            display: grid; place-items: center; font-size: 26px;
            background: linear-gradient(135deg, #6366f1, #0ea5e9);
            box-shadow: 0 10px 30px rgba(99,102,241,0.4);
        }
        h2 { margin: 0 0 6px; font-size: 21px; color: #fff; letter-spacing: -0.2px; }
        p { margin: 0 0 22px; font-size: 13px; color: #8b93a7; }
        input {
            width: 100%; padding: 13px 14px; margin-bottom: 12px;
            background: #0d0e13; border: 1px solid #272a36; color: #fff;
            border-radius: 11px; font-size: 14px; text-align: center;
            transition: border-color .15s, box-shadow .15s;
        }
        input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99,102,241,0.18); }
        button {
            width: 100%; padding: 13px; border: none; border-radius: 11px; cursor: pointer;
            font-size: 14px; font-weight: 600; color: #fff;
            background: linear-gradient(135deg, #6366f1, #3b82f6);
            transition: transform .1s, filter .15s;
        }
        button:hover { filter: brightness(1.1); }
        button:active { transform: translateY(1px); }
        button:disabled { opacity: .6; cursor: wait; }
        .err { min-height: 18px; margin-top: 12px; font-size: 12.5px; color: #fca5a5; }
        .shake { animation: shake .35s; }
        @keyframes shake { 25% { transform: translateX(-6px);} 75% { transform: translateX(6px);} }
    </style>
</head>
<body>
    <div class="card" id="card">
        <div class="logo">🔐</div>
        <h2>Subscription Hub</h2>
        <p>Enter your dashboard password to continue</p>
        <input type="password" id="passInput" placeholder="Password" autocomplete="current-password" autofocus>
        <button id="loginBtn" onclick="login()">Sign in</button>
        <div class="err" id="err"></div>
    </div>
    <script>
        const input = document.getElementById('passInput');
        input.addEventListener('keydown', function (e) { if (e.key === 'Enter') login(); });
        async function login() {
            const btn = document.getElementById('loginBtn');
            const err = document.getElementById('err');
            err.textContent = '';
            btn.disabled = true;
            try {
                const res = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: input.value })
                });
                if (res.ok) {
                    window.location.reload();
                    return;
                }
                err.textContent = 'Incorrect password. Please try again.';
                const card = document.getElementById('card');
                card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
                input.select();
            } catch (e) {
                err.textContent = 'Network error. Please try again.';
            } finally {
                btn.disabled = false;
            }
        }
    </script>
</body>
</html>
  `;
}

/* ------------------------------------------------------------------ */
/* MAIN DASHBOARD                                                      */
/* ------------------------------------------------------------------ */

function getAdminPanelHTML(baseUrl, serverGroups, rotationChunk, subToken, subTitle) {
  const safeGroupsJson = JSON.stringify(normalizeAllGroups(serverGroups)).replace(/</g, '\\u003c');
  const safeChunk = Number(rotationChunk) >= 1 ? Number(rotationChunk) : DEFAULT_ROTATION_CHUNK;
  const safeTitleJson = JSON.stringify(String(subTitle || DEFAULT_SUB_TITLE)).replace(/</g, '\\u003c');
  const safeSubToken = String(subToken || '482915').replace(/[^0-9]/g, '').slice(0, 6) || '482915';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <title>Subscription Hub</title>
    <style>
        :root {
            --bg: #0b0c10;
            --surface: #14151b;
            --surface-2: #1a1c24;
            --surface-3: #21232d;
            --line: #272a36;
            --line-soft: rgba(255,255,255,0.06);
            --text: #e5e7eb;
            --muted: #8b93a7;
            --muted-2: #656c80;
            --accent: #6366f1;
            --accent-2: #3b82f6;
            --accent-soft: rgba(99,102,241,0.14);
            --green: #10b981;
            --green-soft: rgba(16,185,129,0.14);
            --amber: #f59e0b;
            --red: #ef4444;
            --red-soft: rgba(239,68,68,0.13);
            --radius: 16px;
            --mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
        }
        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            background:
                radial-gradient(1000px 520px at 10% -8%, rgba(99,102,241,0.16), transparent 60%),
                radial-gradient(900px 520px at 100% 0%, rgba(14,165,233,0.10), transparent 60%),
                var(--bg);
            background-attachment: fixed;
            color: var(--text);
            margin: 0;
            padding: 28px 20px 130px;
            display: flex;
            justify-content: center;
            -webkit-font-smoothing: antialiased;
        }
        .container { width: 100%; max-width: 880px; }

        /* ---------- Header ---------- */
        header {
            display: flex; justify-content: space-between; align-items: center;
            gap: 14px; flex-wrap: wrap; margin-bottom: 22px;
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .brand-logo {
            width: 44px; height: 44px; border-radius: 13px; display: grid; place-items: center;
            font-size: 22px; background: linear-gradient(135deg, var(--accent), #0ea5e9);
            box-shadow: 0 8px 24px rgba(99,102,241,0.35);
        }
        h1 { margin: 0; font-size: 22px; color: #fff; letter-spacing: -0.3px; }
        .brand-sub { font-size: 12.5px; color: var(--muted); margin-top: 2px; }

        /* ---------- Buttons ---------- */
        .btn {
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            color: #fff; border: none; padding: 9px 16px; border-radius: 10px;
            cursor: pointer; font-weight: 600; font-size: 13px; font-family: inherit;
            transition: filter .15s, transform .1s, background .15s;
            white-space: nowrap;
        }
        .btn:hover { filter: brightness(1.12); }
        .btn:active { transform: translateY(1px); }
        .btn:disabled { opacity: .55; cursor: not-allowed; filter: none; }
        .btn-ghost {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            padding: 7px 12px; font-size: 12px; font-weight: 600;
        }
        .btn-ghost:hover { background: var(--surface-3); color: #fff; filter: none; }
        .btn-danger-ghost {
            background: var(--red-soft); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5;
            padding: 7px 12px; font-size: 12px; font-weight: 600;
        }
        .btn-danger-ghost:hover { background: rgba(239,68,68,0.22); color: #fecaca; filter: none; }
        .icon-btn {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            width: 30px; height: 30px; border-radius: 8px; cursor: pointer; font-size: 14px;
            display: inline-flex; align-items: center; justify-content: center; padding: 0;
            transition: background .15s;
        }
        .icon-btn:hover { background: var(--surface-3); color: #fff; }
        .icon-btn:disabled { opacity: .3; cursor: default; }

        /* ---------- Stats ---------- */
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
        .stat {
            background: var(--surface); border: 1px solid var(--line-soft); border-radius: 14px;
            padding: 14px 16px;
        }
        .stat-label { font-size: 11.5px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted-2); font-weight: 600; }
        .stat-value { font-size: 26px; font-weight: 700; color: #fff; margin-top: 4px; letter-spacing: -0.5px; }
        .stat-value small { font-size: 12px; font-weight: 500; color: var(--muted); letter-spacing: 0; margin-left: 4px; }

        /* ---------- Generic card ---------- */
        .card {
            background: var(--surface); border: 1px solid var(--line-soft);
            border-radius: var(--radius); padding: 16px 18px; margin-bottom: 16px;
        }
        .card-title { font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
        .card-desc { font-size: 12px; color: var(--muted); margin-top: 3px; line-height: 1.5; }

        /* ---------- Subscription link ---------- */
        .sub-card { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; }
        .sub-card-main { min-width: 0; flex: 1; }
        .sub-url-row {
            margin-top: 8px; display: flex; align-items: center; gap: 8px;
            background: #0d0e13; border: 1px solid var(--line); border-radius: 10px; padding: 9px 12px;
        }
        .sub-url-row code { color: #7dd3fc; font-family: var(--mono); font-size: 13px; word-break: break-all; flex: 1; }
        .code-badge {
            background: var(--green-soft); border: 1px solid rgba(16,185,129,.35); color: #6ee7b7;
            font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-family: var(--mono);
        }
        .sub-card-actions { display: flex; gap: 8px; flex-wrap: wrap; }

        /* ---------- Divide preference ---------- */
        .divide-top { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; }
        .segmented { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
        .chunk-preset-btn {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            min-width: 36px; padding: 6px 11px; border-radius: 9px; font-size: 12.5px; font-weight: 700;
            cursor: pointer; transition: all .15s; font-family: inherit;
        }
        .chunk-preset-btn:hover { background: var(--surface-3); color: #fff; }
        .chunk-preset-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; box-shadow: 0 4px 14px rgba(99,102,241,.35); }
        .chunk-custom-wrap {
            display: flex; align-items: center; gap: 6px; background: #0d0e13;
            border: 1px solid var(--line); border-radius: 9px; padding: 3px 9px;
        }
        .chunk-custom-wrap span { font-size: 11px; color: var(--muted); }
        .chunk-custom-input {
            width: 46px; background: transparent; border: none; color: #fff; font-size: 13px;
            font-weight: 700; text-align: center; padding: 4px 0; font-family: inherit;
        }
        .chunk-custom-input:focus { outline: none; }

        /* Rotation preview */
        .preview-toggle {
            margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--line);
            display: flex; justify-content: space-between; align-items: center; gap: 10px;
            cursor: pointer; user-select: none;
        }
        .preview-toggle .card-title { font-size: 12.5px; color: #cbd5e1; }
        .chev { display: inline-block; transition: transform .18s; color: var(--muted); font-size: 12px; }
        .preview-open .chev { transform: rotate(90deg); }
        .preview-body { display: none; margin-top: 10px; }
        .preview-open .preview-body { display: block; }
        .preview-legend { font-size: 11.5px; color: var(--muted); margin-bottom: 8px; line-height: 1.5; }
        .batches { display: flex; flex-wrap: wrap; gap: 6px; }
        .batch-pill {
            display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
            padding: 4px 9px; border-radius: 999px; color: #e2e8f0;
            border: 1px solid transparent;
        }
        .batch-pill b { font-family: var(--mono); font-weight: 700; }
        .batch-pill.partial { border-style: dashed; border-color: rgba(251,191,36,.7); }
        .batch-sep { color: var(--muted-2); font-size: 11px; align-self: center; }
        .batch-more { font-size: 11.5px; color: var(--muted); align-self: center; }

        .hint { font-size: 12px; color: var(--muted); margin: 4px 2px 12px; }

        /* ---------- Groups ---------- */
        .server-group {
            position: relative;
            background: var(--surface); border: 1px solid var(--line-soft);
            border-radius: var(--radius); padding: 16px 18px 14px 22px;
            transition: border-color .15s, box-shadow .15s;
        }
        .server-group::before {
            content: ''; position: absolute; left: 0; top: 14px; bottom: 14px; width: 4px;
            border-radius: 0 4px 4px 0; background: var(--gc, var(--accent));
        }
        .server-group:hover { border-color: rgba(255,255,255,0.12); }
        .server-group.dragging { opacity: .35; }
        .server-group.collapsed .group-body { display: none; }
        .server-group.collapsed .group-header { margin-bottom: 0; }

        .drop-zone {
            height: 18px; border-radius: 8px; border: 2px dashed transparent;
            display: flex; align-items: center; justify-content: center;
            transition: background-color .1s, border-color .1s;
        }
        body.is-dragging .drop-zone { border-color: #30333f; }
        body.is-dragging .drop-zone.hover { border-color: var(--accent); border-style: solid; background: rgba(99,102,241,.22); }
        .drop-zone::after { content: ''; font-size: 11px; letter-spacing: .4px; color: transparent; }
        body.is-dragging .drop-zone.hover::after { content: 'Drop here'; color: #c7d2fe; font-weight: 700; }

        .group-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
        .header-left { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 220px; }
        .header-right { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
        .drag-handle { color: var(--muted-2); font-size: 18px; user-select: none; cursor: grab; padding: 2px 5px; border-radius: 6px; }
        .drag-handle:hover { color: #cbd5e1; background: var(--surface-2); }
        .drag-handle:active { cursor: grabbing; }
        .collapse-btn { background: none; border: none; color: var(--muted); cursor: pointer; padding: 4px; font-size: 12px; border-radius: 6px; }
        .collapse-btn:hover { background: var(--surface-2); color: #fff; }
        .server-group:not(.collapsed) .collapse-btn .chev { transform: rotate(90deg); }
        .group-title {
            background: transparent; border: none; color: #fff; font-size: 17px; font-weight: 700;
            border-bottom: 1px dashed transparent; padding: 3px 2px; flex: 1; min-width: 0; font-family: inherit;
            letter-spacing: -0.2px;
        }
        .group-title:hover { border-bottom-color: #3a3e4c; }
        .group-title:focus { outline: none; border-bottom-color: var(--accent); }

        .config-count-badge {
            background: var(--accent-soft); border: 1px solid rgba(99,102,241,.3); color: #c7d2fe;
            font-size: 11.5px; font-weight: 700; padding: 3px 10px; border-radius: 999px; white-space: nowrap;
        }
        .config-count-badge.empty { background: var(--red-soft); border-color: rgba(239,68,68,.3); color: #fca5a5; }
        .config-count-badge.sub-mode { background: var(--green-soft); border-color: rgba(16,185,129,.35); color: #6ee7b7; }

        .chips { display: flex; flex-wrap: wrap; gap: 5px; margin: 0 0 10px; min-height: 0; }
        .chips:empty { display: none; }
        .chip {
            font-family: var(--mono); font-size: 10.5px; font-weight: 700; text-transform: uppercase;
            letter-spacing: .4px; padding: 2px 7px; border-radius: 6px;
            background: var(--surface-3); color: #aab2c5; border: 1px solid var(--line);
        }
        .chip.v6 { background: rgba(14,165,233,.14); border-color: rgba(14,165,233,.35); color: #7dd3fc; }

        .mode-bar { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
        .mode-switch-group { display: inline-flex; background: #0d0e13; border: 1px solid var(--line); border-radius: 10px; padding: 3px; gap: 3px; }
        .mode-btn {
            background: transparent; border: none; color: var(--muted); font-size: 12px; font-weight: 700;
            padding: 6px 12px; border-radius: 7px; cursor: pointer; transition: all .15s; font-family: inherit;
        }
        .mode-btn:hover { color: #fff; }
        .mode-btn.active { background: var(--accent); color: #fff; }
        .mode-btn.active.sub-active { background: #059669; }
        .sub-actions-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .sub-status-text { font-size: 11.5px; color: var(--muted); }
        .sub-status-text.ok { color: #6ee7b7; }
        .sub-status-text.err { color: #fca5a5; }

        textarea {
            width: 100%; height: 130px; background: #0d0e13; border: 1px solid var(--line);
            border-radius: 11px; color: #cbd5e1; padding: 11px 12px; font-family: var(--mono);
            font-size: 12.5px; line-height: 1.55; resize: vertical; transition: border-color .15s, box-shadow .15s;
        }
        textarea.sub-textarea { height: 84px; border-color: rgba(16,185,129,.35); }
        textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 4px rgba(99,102,241,.14); }
        textarea.sub-textarea:focus { border-color: #10b981; box-shadow: 0 0 0 4px rgba(16,185,129,.14); }
        body.is-dragging textarea, body.is-dragging input, body.is-dragging .floating-save-bar { pointer-events: none; }

        .group-footer {
            margin-top: 9px; display: flex; flex-wrap: wrap; align-items: center;
            justify-content: space-between; gap: 8px; font-size: 11.5px; color: var(--muted-2);
        }
        .group-footer code { color: var(--muted); font-family: var(--mono); font-size: 11px; }

        .empty-groups-state {
            background: var(--surface); border: 1px dashed #353846; border-radius: var(--radius);
            padding: 44px 20px; text-align: center; color: var(--muted);
        }

        /* ---------- Save bar ---------- */
        .floating-save-bar {
            position: fixed; bottom: 0; left: 0; right: 0; z-index: 40;
            background: rgba(11,12,16,.82); backdrop-filter: blur(14px);
            border-top: 1px solid var(--line); padding: 12px 20px; display: flex; justify-content: center;
        }
        .floating-save-inner { width: 100%; max-width: 880px; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
        .save-status { font-size: 12.5px; color: var(--muted); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .save-status .sep { opacity: .5; }
        .dirty-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px rgba(16,185,129,.15); display: inline-block; }
        .dirty-dot.dirty { background: var(--amber); box-shadow: 0 0 0 4px rgba(245,158,11,.18); }
        .floating-actions { display: flex; align-items: center; gap: 10px; }
        kbd { font-family: var(--mono); font-size: 10.5px; background: var(--surface-3); border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 5px; padding: 1px 5px; color: #aab2c5; }

        /* ---------- Toasts ---------- */
        .toasts { position: fixed; top: 18px; right: 18px; z-index: 100; display: flex; flex-direction: column; gap: 8px; max-width: calc(100vw - 36px); }
        .toast {
            background: var(--surface-2); border: 1px solid var(--line); border-left: 4px solid var(--accent);
            color: #e5e7eb; padding: 11px 15px; border-radius: 10px; font-size: 13px; font-weight: 500;
            box-shadow: 0 12px 30px rgba(0,0,0,.45); animation: toastIn .22s ease-out;
        }
        .toast.ok { border-left-color: var(--green); }
        .toast.err { border-left-color: var(--red); }
        .toast.out { opacity: 0; transform: translateX(14px); transition: all .22s; }
        @keyframes toastIn { from { opacity: 0; transform: translateX(14px); } to { opacity: 1; transform: none; } }

        @media (max-width: 620px) {
            body { padding: 18px 12px 150px; }
            .stats { grid-template-columns: repeat(3, 1fr); gap: 8px; }
            .stat { padding: 11px 12px; }
            .stat-value { font-size: 21px; }
            .server-group { padding: 14px 14px 12px 18px; }
            kbd, .kbd-hint { display: none; }
        }
    </style>
</head>
<body>
    <div class="toasts" id="toasts"></div>

    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-logo">🛰️</div>
                <div>
                    <h1>Config Manager</h1>
                    <div class="brand-sub">Group, rotate and publish your subscription</div>
                </div>
            </div>
            <button class="btn" onclick="addNewGroup()">+ Add Server Group</button>
        </header>

        <div class="stats">
            <div class="stat"><div class="stat-label">Configs</div><div class="stat-value" id="statConfigs">0</div></div>
            <div class="stat"><div class="stat-label">Groups</div><div class="stat-value" id="statGroups">0</div></div>
            <div class="stat"><div class="stat-label">Batches</div><div class="stat-value" id="statBatches">0<small>per output</small></div></div>
        </div>

        <div class="card sub-card">
            <div class="sub-card-main">
                <div class="card-title">
                    <span>Protected subscription link</span>
                    <span class="code-badge" id="subTokenBadge">code ${safeSubToken}</span>
                </div>
                <div class="sub-url-row"><code id="subUrl">${baseUrl}/sub/${safeSubToken}</code></div>
            </div>
            <div class="sub-card-actions">
                <button class="btn btn-ghost" id="regenTokenBtn" onclick="regenerateSubToken()" title="Generate a new random 6-digit subscription link code">New code</button>
                <button class="btn" id="copySubBtn" onclick="copySubLink()">Copy link</button>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Subscription name</div>
            <div class="card-desc">Shown by apps as the name of the subscription (sent in the Profile-Title header). Apps update it on the next refresh.</div>
            <div class="sub-url-row">
                <input type="text" id="subTitleInput" maxlength="100" placeholder="Subscription name" oninput="onSubTitleInput(this.value)" style="width:100%;background:transparent;border:none;color:#fff;font-size:14px;font-family:inherit;padding:4px 2px;outline:none;">
            </div>
        </div>

        <div class="card" id="divideCard">
            <div class="divide-top">
                <div>
                    <div class="card-title">Divide preference</div>
                    <div class="card-desc" id="divideHintText">
                        Output rotates through groups ${safeChunk} configs at a time, in the order shown below.
                    </div>
                </div>
                <div class="segmented">
                    <button type="button" class="chunk-preset-btn" data-chunk="1" onclick="setRotationChunk(1)">1</button>
                    <button type="button" class="chunk-preset-btn" data-chunk="2" onclick="setRotationChunk(2)">2</button>
                    <button type="button" class="chunk-preset-btn" data-chunk="3" onclick="setRotationChunk(3)">3</button>
                    <button type="button" class="chunk-preset-btn" data-chunk="5" onclick="setRotationChunk(5)">5</button>
                    <button type="button" class="chunk-preset-btn" data-chunk="10" onclick="setRotationChunk(10)">10</button>
                    <div class="chunk-custom-wrap">
                        <span>Custom</span>
                        <input type="number" id="customChunkInput" class="chunk-custom-input" min="1" max="500" value="${safeChunk}" oninput="onCustomChunkInput(this.value)">
                    </div>
                </div>
            </div>
            <div class="preview-toggle" onclick="togglePreview()">
                <div class="card-title"><span class="chev">▶</span><span>Output order preview</span></div>
                <span class="sub-status-text" id="previewSummary"></span>
            </div>
            <div class="preview-body">
                <div class="preview-legend">Each pill is one batch in the exact order your app will list them. A dashed amber outline means that group had fewer configs left than the batch size (its last, partial batch).</div>
                <div class="batches" id="batches"></div>
            </div>
        </div>

        <div class="hint">Each group can use Direct Configs or Subscription Links. Drag the ⠿ handle onto a highlighted gap, or use the arrows to reorder.</div>

        <div id="groupsContainer"></div>
    </div>

    <div class="floating-save-bar">
        <div class="floating-save-inner">
            <div class="save-status">
                <span class="dirty-dot" id="dirtyDot"></span>
                <span id="saveStatusText">All changes saved</span>
                <span class="sep">•</span>
                <span id="floatingTotalText">0 configs across 0 groups</span>
                <span class="sep">•</span>
                <span id="floatingChunkText">Divide: ${safeChunk}/group</span>
            </div>
            <div class="floating-actions">
                <button class="btn btn-ghost" onclick="addNewGroup()">+ Group</button>
                <button class="btn" id="saveAllBtn" onclick="saveAll()">Save changes <kbd>Ctrl S</kbd></button>
            </div>
        </div>
    </div>

    <script>
        const NEWLINE_CHAR = String.fromCharCode(10);
        const CR_CHAR = String.fromCharCode(13);
        const BASE_ORIGIN = ${JSON.stringify(baseUrl)};
        const SCHEME_RE = /^[a-z][a-z0-9+.\\-]*:\\/\\//i;
        const SAVE_LABEL = 'Save changes <kbd>Ctrl S</kbd>';
        let dataGroups = ${safeGroupsJson};
        let currentRotationChunk = ${safeChunk};
        let currentSubToken = ${JSON.stringify(safeSubToken)};
        let currentSubTitle = ${safeTitleJson};
        let dragFromIndex = null;
        let dropPosition = null;
        let hasUnsavedChanges = false;

        // Drag auto-scroller state
        let dragPointerX = 0;
        let dragPointerY = 0;
        let dragScrollRAF = null;

        function showToast(message, type) {
            const box = document.getElementById('toasts');
            const t = document.createElement('div');
            t.className = 'toast' + (type ? ' ' + type : '');
            t.textContent = message;
            box.appendChild(t);
            setTimeout(function() {
                t.classList.add('out');
                setTimeout(function() { t.remove(); }, 250);
            }, 2800);
        }

        function hueFor(name) {
            let h = 0;
            for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
            return h;
        }
        function colorFor(name) { return 'hsl(' + hueFor(name) + ', 68%, 60%)'; }
        function softColorFor(name) { return 'hsla(' + hueFor(name) + ', 68%, 55%, 0.20)'; }

        function getScheme(line) {
            const m = String(line || '').trim().match(/^([a-z][a-z0-9+.\\-]*):\\/\\//i);
            return m ? m[1].toLowerCase() : '';
        }
        function isHttpLine(line) {
            const s = String(line || '').trim().toLowerCase();
            return s.startsWith('http://') || s.startsWith('https://');
        }

        // Any "scheme://" begins a NEW entry, same rule as the server
        function parseLines(text) {
            const rawLines = String(text || '')
                .split(NEWLINE_CHAR)
                .map(line => line.replace(CR_CHAR, '').trim())
                .filter(line => line !== '');
            const stitched = [];
            for (let i = 0; i < rawLines.length; i++) {
                const line = rawLines[i];
                if (SCHEME_RE.test(line)) {
                    stitched.push(line);
                } else if (
                    stitched.length > 0 &&
                    !/\\s/.test(line) &&
                    !line.startsWith('//') &&
                    !line.startsWith(';') &&
                    !line.startsWith('#')
                ) {
                    stitched[stitched.length - 1] += line;
                }
            }
            return stitched;
        }

        function isIPv6Config(line) {
            const s = String(line || '');
            const at = s.lastIndexOf('@');
            if (at === -1) return /\\[[0-9a-f:]+\\]/i.test(s);
            const rest = s.slice(at + 1).split(/[?\\/#]/)[0];
            return (rest.match(/:/g) || []).length >= 2;
        }

        function normalizeGroupKey(str) {
            return String(str || '').trim().split(' ').filter(Boolean).join('_');
        }

        function ensureGroupObj(entry) {
            if (Array.isArray(entry)) {
                const lines = entry.map(c => String(c || '').trim()).filter(Boolean);
                const subUrls = lines.filter(isHttpLine);
                const configs = lines.filter(l => !isHttpLine(l));
                return {
                    mode: (subUrls.length > 0 && configs.length === 0) ? 'sub' : 'configs',
                    configs: configs,
                    subUrls: subUrls,
                    cachedSubConfigs: []
                };
            }
            if (entry && typeof entry === 'object') {
                return {
                    mode: entry.mode === 'sub' ? 'sub' : 'configs',
                    configs: Array.isArray(entry.configs) ? entry.configs : [],
                    subUrls: Array.isArray(entry.subUrls) ? entry.subUrls : [],
                    cachedSubConfigs: Array.isArray(entry.cachedSubConfigs) ? entry.cachedSubConfigs : []
                };
            }
            return { mode: 'configs', configs: [], subUrls: [], cachedSubConfigs: [] };
        }

        function setRotationChunk(val) {
            const parsed = Math.max(1, Math.min(500, parseInt(val, 10) || 1));
            currentRotationChunk = parsed;
            const input = document.getElementById('customChunkInput');
            if (input && parseInt(input.value, 10) !== parsed) input.value = parsed;
            updateChunkUI();
            updateAllCounts();
            markDirty(true);
        }

        function onCustomChunkInput(val) {
            const parsed = parseInt(val, 10);
            if (!Number.isFinite(parsed) || parsed < 1) return;
            currentRotationChunk = Math.min(500, parsed);
            updateChunkUI();
            updateAllCounts();
            markDirty(true);
        }

        function updateChunkUI() {
            document.querySelectorAll('.chunk-preset-btn').forEach(btn => {
                const c = parseInt(btn.getAttribute('data-chunk'), 10);
                btn.classList.toggle('active', c === currentRotationChunk);
            });
            const hint = document.getElementById('divideHintText');
            if (hint) {
                hint.textContent = 'Output rotates through groups ' + currentRotationChunk + (currentRotationChunk === 1 ? ' config' : ' configs') + ' at a time, in the order shown below.';
            }
            const floatingChunk = document.getElementById('floatingChunkText');
            if (floatingChunk) floatingChunk.textContent = 'Divide: ' + currentRotationChunk + '/group';
        }

        function onSubTitleInput(val) {
            currentSubTitle = String(val || '');
            markDirty(true);
        }

        function togglePreview() {
            document.getElementById('divideCard').classList.toggle('preview-open');
        }

        function markDirty(isDirty) {
            hasUnsavedChanges = isDirty;
            const dot = document.getElementById('dirtyDot');
            const statusText = document.getElementById('saveStatusText');
            if (!dot || !statusText) return;
            dot.classList.toggle('dirty', isDirty);
            statusText.textContent = isDirty ? 'Unsaved changes' : 'All changes saved';
            statusText.style.color = isDirty ? '#fcd34d' : '';
        }

        function getGroupEffectiveCount(groupEl) {
            const mode = groupEl.dataset.mode === 'sub' ? 'sub' : 'configs';
            if (mode === 'sub') {
                const subArea = groupEl.querySelector('.sub-textarea');
                const subUrls = parseLines(subArea ? subArea.value : '').filter(isHttpLine);
                const cached = Array.isArray(groupEl._cachedSubConfigs) ? groupEl._cachedSubConfigs : [];
                return { mode: 'sub', count: cached.length, subUrlCount: subUrls.length, lines: cached };
            }
            const cfgArea = groupEl.querySelector('.configs-textarea');
            const lines = parseLines(cfgArea ? cfgArea.value : '');
            return { mode: 'configs', count: lines.length, subUrlCount: 0, lines: lines };
        }

        function renderChips(container, lines) {
            container.innerHTML = '';
            if (!lines || lines.length === 0) return;
            const counts = {};
            let v6 = 0;
            lines.forEach(function(l) {
                const s = getScheme(l) || 'other';
                counts[s] = (counts[s] || 0) + 1;
                if (isIPv6Config(l)) v6++;
            });
            Object.keys(counts).forEach(function(s) {
                const c = document.createElement('span');
                c.className = 'chip';
                c.textContent = s + ' ' + counts[s];
                container.appendChild(c);
            });
            if (v6 > 0) {
                const c = document.createElement('span');
                c.className = 'chip v6';
                c.textContent = 'ipv6 ' + v6;
                container.appendChild(c);
            }
        }

        function renderPreview(groupInfos) {
            const box = document.getElementById('batches');
            const summary = document.getElementById('previewSummary');
            if (!box) return;
            box.innerHTML = '';
            const chunk = currentRotationChunk;
            const batches = [];
            let offset = 0;
            let guard = 0;
            while (guard++ < 5000) {
                let added = false;
                for (let i = 0; i < groupInfos.length; i++) {
                    const g = groupInfos[i];
                    const n = Math.min(chunk, g.count - offset);
                    if (n <= 0) continue;
                    added = true;
                    batches.push({ name: g.name, n: n, partial: n < chunk });
                }
                if (!added) break;
                offset += chunk;
            }
            const MAX = 60;
            batches.slice(0, MAX).forEach(function(b, idx) {
                if (idx > 0) {
                    const sep = document.createElement('span');
                    sep.className = 'batch-sep';
                    sep.textContent = '→';
                    box.appendChild(sep);
                }
                const pill = document.createElement('span');
                pill.className = 'batch-pill' + (b.partial ? ' partial' : '');
                pill.style.background = softColorFor(b.name);
                pill.appendChild(document.createTextNode(b.name.replace(/_/g, ' ') + ' '));
                const bold = document.createElement('b');
                bold.textContent = '×' + b.n;
                pill.appendChild(bold);
                if (b.partial) pill.title = 'Partial batch: this group has fewer than ' + chunk + ' configs left';
                box.appendChild(pill);
            });
            if (batches.length > MAX) {
                const more = document.createElement('span');
                more.className = 'batch-more';
                more.textContent = '… +' + (batches.length - MAX) + ' more';
                box.appendChild(more);
            }
            if (batches.length === 0) {
                const none = document.createElement('span');
                none.className = 'batch-more';
                none.textContent = 'Nothing to preview yet.';
                box.appendChild(none);
            }
            const partials = batches.filter(b => b.partial).length;
            if (summary) {
                summary.textContent = batches.length + (batches.length === 1 ? ' batch' : ' batches') + (partials ? ' • ' + partials + ' partial' : '');
            }
            return batches.length;
        }

        // Recalculate counts, chips, preview and totals without losing focus
        function updateAllCounts() {
            let totalConfigs = 0;
            const groupElements = document.querySelectorAll('.server-group');
            const totalGroups = groupElements.length;
            const infos = [];

            groupElements.forEach(el => {
                const info = getGroupEffectiveCount(el);
                totalConfigs += info.count;

                const titleInput = el.querySelector('.group-title');
                const cleanTitle = (titleInput && titleInput.value.trim()) ? titleInput.value.trim() : 'Group';
                const keyName = normalizeGroupKey(cleanTitle) || 'Group';
                infos.push({ name: keyName, count: info.count });

                const color = colorFor(keyName);
                el.style.setProperty('--gc', color);

                const badge = el.querySelector('.config-count-badge');
                if (badge) {
                    if (info.mode === 'sub') {
                        if (info.subUrlCount === 0) {
                            badge.textContent = '0 sub links';
                            badge.className = 'config-count-badge empty';
                        } else if (info.count > 0) {
                            badge.textContent = info.subUrlCount + (info.subUrlCount === 1 ? ' link' : ' links') + ' • ' + info.count + (info.count === 1 ? ' config' : ' configs');
                            badge.className = 'config-count-badge sub-mode';
                        } else {
                            badge.textContent = info.subUrlCount + (info.subUrlCount === 1 ? ' link' : ' links') + ' (sync on save)';
                            badge.className = 'config-count-badge sub-mode';
                        }
                    } else {
                        badge.textContent = info.count + (info.count === 1 ? ' config' : ' configs');
                        badge.className = 'config-count-badge' + (info.count === 0 ? ' empty' : '');
                    }
                }

                const chips = el.querySelector('.chips');
                if (chips) renderChips(chips, info.lines);

                const prefixCode = el.querySelector('.group-prefix-code');
                if (prefixCode) prefixCode.textContent = '#' + cleanTitle + ' - <IP>';

                const roundsSpan = el.querySelector('.group-rounds-text');
                if (roundsSpan) {
                    const rounds = Math.ceil(info.count / currentRotationChunk);
                    roundsSpan.textContent = rounds + (rounds === 1 ? ' batch' : ' batches') + ' of ' + currentRotationChunk;
                }
            });

            const batchCount = renderPreview(infos) || 0;

            document.getElementById('statConfigs').textContent = totalConfigs;
            document.getElementById('statGroups').textContent = totalGroups;
            document.getElementById('statBatches').innerHTML = batchCount + '<small>per output</small>';
            document.getElementById('floatingTotalText').textContent =
                totalConfigs + (totalConfigs === 1 ? ' config' : ' configs') + ' across ' + totalGroups + (totalGroups === 1 ? ' group' : ' groups');
        }

        // Read the current on-screen state back into dataGroups
        function syncFromDOM() {
            const groupEls = document.querySelectorAll('.server-group');
            if (groupEls.length === 0) return;
            const ordered = {};
            groupEls.forEach((el, idx) => {
                const prevName = el.dataset.originalName;
                const prevEntry = ensureGroupObj(dataGroups[prevName]);

                const titleInput = el.querySelector('.group-title');
                let rawName = (titleInput && titleInput.value.trim()) ? normalizeGroupKey(titleInput.value) : prevName;
                if (!rawName) rawName = 'Group_' + (idx + 1);
                let uniqueName = rawName;
                let suffix = 2;
                while (Object.prototype.hasOwnProperty.call(ordered, uniqueName)) {
                    uniqueName = rawName + '_' + suffix;
                    suffix++;
                }
                el.dataset.originalName = uniqueName;
                if (titleInput) titleInput.value = uniqueName.replace(/_/g, ' ');

                const mode = el.dataset.mode === 'sub' ? 'sub' : 'configs';
                const cfgArea = el.querySelector('.configs-textarea');
                const subArea = el.querySelector('.sub-textarea');

                const configs = cfgArea ? parseLines(cfgArea.value) : prevEntry.configs;
                const subUrls = subArea ? parseLines(subArea.value) : prevEntry.subUrls;
                const cachedSubConfigs = Array.isArray(el._cachedSubConfigs) ? el._cachedSubConfigs : prevEntry.cachedSubConfigs;

                ordered[uniqueName] = { mode: mode, configs: configs, subUrls: subUrls, cachedSubConfigs: cachedSubConfigs };
            });
            dataGroups = ordered;
        }

        function deduplicateGroup(groupDiv) {
            const mode = groupDiv.dataset.mode === 'sub' ? 'sub' : 'configs';
            const textarea = groupDiv.querySelector(mode === 'sub' ? '.sub-textarea' : '.configs-textarea');
            if (!textarea) return;
            const lines = parseLines(textarea.value);
            const unique = Array.from(new Set(lines));
            const removed = lines.length - unique.length;
            textarea.value = unique.join(NEWLINE_CHAR);
            updateAllCounts();
            if (removed > 0) {
                markDirty(true);
                showToast('Removed ' + removed + ' duplicate' + (removed === 1 ? '' : 's'), 'ok');
            } else {
                showToast('No duplicates found');
            }
        }

        async function syncGroupSubLinks(groupDiv, statusEl, syncBtn) {
            const subArea = groupDiv.querySelector('.sub-textarea');
            const urls = parseLines(subArea ? subArea.value : '').filter(isHttpLine);
            if (urls.length === 0) {
                statusEl.textContent = 'Enter at least one https:// subscription link first.';
                statusEl.className = 'sub-status-text err';
                return;
            }
            syncBtn.disabled = true;
            syncBtn.textContent = 'Syncing…';
            statusEl.textContent = 'Fetching subscription configs…';
            statusEl.className = 'sub-status-text';
            try {
                const res = await fetch('/fetch-sub', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls: urls })
                });
                const data = await res.json();
                if (data && Array.isArray(data.configs) && data.configs.length > 0) {
                    groupDiv._cachedSubConfigs = data.configs;
                    statusEl.textContent = 'Synced ' + data.configs.length + (data.configs.length === 1 ? ' config' : ' configs') + ' from ' + urls.length + (urls.length === 1 ? ' link' : ' links');
                    statusEl.className = 'sub-status-text ok';
                    syncFromDOM();
                    updateAllCounts();
                    markDirty(true);
                } else {
                    const errMsg = (data && data.errors && data.errors.length > 0) ? data.errors[0] : (data && data.error ? data.error : 'No valid configs returned');
                    statusEl.textContent = errMsg;
                    statusEl.className = 'sub-status-text err';
                }
            } catch (e) {
                statusEl.textContent = 'Failed to fetch subscription link.';
                statusEl.className = 'sub-status-text err';
            } finally {
                syncBtn.disabled = false;
                syncBtn.textContent = 'Sync & count';
            }
        }

        function highlightZone(position) {
            if (dropPosition === position) return;
            dropPosition = position;
            document.querySelectorAll('.drop-zone').forEach(z => {
                z.classList.toggle('hover', parseInt(z.dataset.position, 10) === position);
            });
        }

        function updateDropTargetFromPoint(clientX, clientY) {
            if (dragFromIndex === null) return;
            const groups = document.querySelectorAll('.server-group');
            if (groups.length === 0) return;

            for (let i = 0; i < groups.length; i++) {
                const rect = groups[i].getBoundingClientRect();
                if (clientY >= rect.top - 16 && clientY <= rect.bottom + 16) {
                    const above = (clientY - rect.top) < rect.height / 2;
                    highlightZone(above ? i : i + 1);
                    return;
                }
            }
            const firstRect = groups[0].getBoundingClientRect();
            if (clientY < firstRect.top) { highlightZone(0); return; }
            const lastRect = groups[groups.length - 1].getBoundingClientRect();
            if (clientY > lastRect.bottom) highlightZone(groups.length);
        }

        function startDragAutoScrollLoop() {
            if (dragScrollRAF !== null) return;
            function step() {
                if (dragFromIndex === null) { dragScrollRAF = null; return; }
                const vh = window.innerHeight || document.documentElement.clientHeight;
                const TOP_ZONE = 150;
                const BOTTOM_ZONE = 175;
                let deltaY = 0;

                if (dragPointerY > 0 && dragPointerY < TOP_ZONE) {
                    const intensity = Math.min(1, (TOP_ZONE - dragPointerY) / TOP_ZONE);
                    deltaY = -Math.round(8 + intensity * intensity * 34);
                } else if (dragPointerY > vh - BOTTOM_ZONE) {
                    const intensity = Math.min(1, (dragPointerY - (vh - BOTTOM_ZONE)) / BOTTOM_ZONE);
                    deltaY = Math.round(8 + intensity * intensity * 34);
                }

                if (deltaY !== 0) {
                    window.scrollBy(0, deltaY);
                    updateDropTargetFromPoint(dragPointerX, dragPointerY);
                }
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
            document.querySelectorAll('.drop-zone.hover').forEach(z => z.classList.remove('hover'));
            document.querySelectorAll('.server-group.dragging').forEach(g => g.classList.remove('dragging'));
        }

        function commitDrop() {
            if (dragFromIndex === null || dropPosition === null) { clearDragState(); return; }
            const from = dragFromIndex;
            const pos = dropPosition;
            clearDragState();
            moveGroupToPosition(from, pos);
        }

        function makeDropZone(position) {
            const zone = document.createElement('div');
            zone.className = 'drop-zone';
            zone.dataset.position = position;
            zone.addEventListener('dragover', function(e) {
                if (dragFromIndex === null) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                highlightZone(position);
            });
            zone.addEventListener('drop', function(e) {
                if (dragFromIndex === null) return;
                e.preventDefault();
                e.stopPropagation();
                highlightZone(position);
                commitDrop();
            });
            return zone;
        }

        function renderGroups() {
            const container = document.getElementById('groupsContainer');
            container.innerHTML = '';

            const names = Object.keys(dataGroups);

            if (names.length === 0) {
                const emptyBox = document.createElement('div');
                emptyBox.className = 'empty-groups-state';
                emptyBox.innerHTML = '<div style="margin-bottom: 14px; font-size: 14px;">No server groups yet. Add your first group to paste entries or subscription links.</div><button class="btn" onclick="addNewGroup()">+ Add Server Group</button>';
                container.appendChild(emptyBox);
                updateAllCounts();
                return;
            }

            container.appendChild(makeDropZone(0));

            names.forEach((groupName, index) => {
                const entry = ensureGroupObj(dataGroups[groupName]);
                dataGroups[groupName] = entry;

                const groupDiv = document.createElement('div');
                groupDiv.className = 'server-group';
                groupDiv.dataset.originalName = groupName;
                groupDiv.dataset.index = index;
                groupDiv.dataset.mode = entry.mode;
                groupDiv._cachedSubConfigs = entry.cachedSubConfigs;

                const headerDiv = document.createElement('div');
                headerDiv.className = 'group-header';

                const leftDiv = document.createElement('div');
                leftDiv.className = 'header-left';

                const handle = document.createElement('span');
                handle.className = 'drag-handle';
                handle.textContent = '\\u283F';
                handle.title = 'Drag to reorder this group';
                handle.draggable = true;

                handle.addEventListener('dragstart', function(e) {
                    dragFromIndex = index;
                    dropPosition = null;
                    dragPointerX = e.clientX;
                    dragPointerY = e.clientY;
                    e.dataTransfer.effectAllowed = 'move';
                    e.dataTransfer.setData('text/plain', groupName);
                    if (e.dataTransfer.setDragImage) e.dataTransfer.setDragImage(headerDiv, 24, 16);
                    setTimeout(function() {
                        if (dragFromIndex === null) return;
                        document.body.classList.add('is-dragging');
                        groupDiv.classList.add('dragging');
                        startDragAutoScrollLoop();
                    }, 0);
                });
                handle.addEventListener('dragend', function() { clearDragState(); });

                const collapseBtn = document.createElement('button');
                collapseBtn.type = 'button';
                collapseBtn.className = 'collapse-btn';
                collapseBtn.title = 'Collapse / expand';
                collapseBtn.innerHTML = '<span class="chev">\\u25B6</span>';
                collapseBtn.onclick = function() { groupDiv.classList.toggle('collapsed'); };

                const titleInput = document.createElement('input');
                titleInput.type = 'text';
                titleInput.className = 'group-title';
                titleInput.value = groupName.replace(/_/g, ' ');
                titleInput.addEventListener('input', function() { updateAllCounts(); markDirty(true); });
                titleInput.onchange = function() { updateGroupName(titleInput); };

                const countBadge = document.createElement('span');
                countBadge.className = 'config-count-badge';

                leftDiv.appendChild(handle);
                leftDiv.appendChild(collapseBtn);
                leftDiv.appendChild(titleInput);
                leftDiv.appendChild(countBadge);

                const rightDiv = document.createElement('div');
                rightDiv.className = 'header-right';

                const dedupBtn = document.createElement('button');
                dedupBtn.className = 'btn btn-ghost';
                dedupBtn.textContent = 'Dedupe';
                dedupBtn.title = 'Remove duplicate & empty lines in this group';
                dedupBtn.onclick = function() { deduplicateGroup(groupDiv); };

                const upBtn = document.createElement('button');
                upBtn.className = 'icon-btn';
                upBtn.textContent = '\\u2191';
                upBtn.title = 'Move group up';
                upBtn.disabled = index === 0;
                upBtn.onclick = function() { moveGroup(index, -1); };

                const downBtn = document.createElement('button');
                downBtn.className = 'icon-btn';
                downBtn.textContent = '\\u2193';
                downBtn.title = 'Move group down';
                downBtn.disabled = index === names.length - 1;
                downBtn.onclick = function() { moveGroup(index, 1); };

                const delBtn = document.createElement('button');
                delBtn.className = 'btn btn-danger-ghost';
                delBtn.textContent = 'Delete';
                delBtn.onclick = function() { deleteGroup(groupName); };

                rightDiv.appendChild(dedupBtn);
                rightDiv.appendChild(upBtn);
                rightDiv.appendChild(downBtn);
                rightDiv.appendChild(delBtn);

                headerDiv.appendChild(leftDiv);
                headerDiv.appendChild(rightDiv);

                const body = document.createElement('div');
                body.className = 'group-body';

                const chips = document.createElement('div');
                chips.className = 'chips';

                const modeBar = document.createElement('div');
                modeBar.className = 'mode-bar';

                const switchGroup = document.createElement('div');
                switchGroup.className = 'mode-switch-group';

                const directModeBtn = document.createElement('button');
                directModeBtn.type = 'button';
                directModeBtn.className = 'mode-btn' + (entry.mode === 'configs' ? ' active' : '');
                directModeBtn.textContent = 'Direct configs';

                const subModeBtn = document.createElement('button');
                subModeBtn.type = 'button';
                subModeBtn.className = 'mode-btn' + (entry.mode === 'sub' ? ' active sub-active' : '');
                subModeBtn.textContent = 'Subscription link';

                switchGroup.appendChild(directModeBtn);
                switchGroup.appendChild(subModeBtn);

                const subRight = document.createElement('div');
                subRight.className = 'sub-actions-right';
                subRight.style.display = entry.mode === 'sub' ? 'flex' : 'none';

                const subStatus = document.createElement('span');
                subStatus.className = 'sub-status-text' + (entry.cachedSubConfigs.length > 0 ? ' ok' : '');
                subStatus.textContent = entry.cachedSubConfigs.length > 0
                    ? ('Synced ' + entry.cachedSubConfigs.length + (entry.cachedSubConfigs.length === 1 ? ' config' : ' configs'))
                    : 'Fetched live when your app updates, or on save';

                const syncSubBtn = document.createElement('button');
                syncSubBtn.type = 'button';
                syncSubBtn.className = 'btn btn-ghost';
                syncSubBtn.textContent = 'Sync & count';
                syncSubBtn.onclick = function() { syncGroupSubLinks(groupDiv, subStatus, syncSubBtn); };

                subRight.appendChild(subStatus);
                subRight.appendChild(syncSubBtn);

                modeBar.appendChild(switchGroup);
                modeBar.appendChild(subRight);

                const cfgArea = document.createElement('textarea');
                cfgArea.className = 'configs-textarea';
                cfgArea.spellcheck = false;
                cfgArea.placeholder = 'Paste entries here, one per line\\u2026';
                cfgArea.value = entry.configs.join(NEWLINE_CHAR);
                cfgArea.style.display = entry.mode === 'configs' ? 'block' : 'none';
                cfgArea.addEventListener('input', function() { updateAllCounts(); markDirty(true); });

                const subArea = document.createElement('textarea');
                subArea.className = 'sub-textarea';
                subArea.spellcheck = false;
                subArea.placeholder = 'Paste subscription link(s) here (https://\\u2026 one per line)\\u2026';
                subArea.value = entry.subUrls.join(NEWLINE_CHAR);
                subArea.style.display = entry.mode === 'sub' ? 'block' : 'none';
                subArea.addEventListener('input', function() { updateAllCounts(); markDirty(true); });

                directModeBtn.onclick = function() {
                    if (groupDiv.dataset.mode === 'configs') return;
                    groupDiv.dataset.mode = 'configs';
                    directModeBtn.className = 'mode-btn active';
                    subModeBtn.className = 'mode-btn';
                    cfgArea.style.display = 'block';
                    subArea.style.display = 'none';
                    subRight.style.display = 'none';
                    syncFromDOM();
                    updateAllCounts();
                    markDirty(true);
                };

                subModeBtn.onclick = function() {
                    if (groupDiv.dataset.mode === 'sub') return;
                    groupDiv.dataset.mode = 'sub';
                    directModeBtn.className = 'mode-btn';
                    subModeBtn.className = 'mode-btn active sub-active';
                    cfgArea.style.display = 'none';
                    subArea.style.display = 'block';
                    subRight.style.display = 'flex';
                    syncFromDOM();
                    updateAllCounts();
                    markDirty(true);
                };

                const footerDiv = document.createElement('div');
                footerDiv.className = 'group-footer';

                const prefixSpan = document.createElement('span');
                prefixSpan.appendChild(document.createTextNode('Renamed to: '));
                const prefixCode = document.createElement('code');
                prefixCode.className = 'group-prefix-code';
                prefixSpan.appendChild(prefixCode);

                const roundsSpan = document.createElement('span');
                roundsSpan.className = 'group-rounds-text';

                footerDiv.appendChild(prefixSpan);
                footerDiv.appendChild(roundsSpan);

                groupDiv.addEventListener('dragover', function(e) {
                    if (dragFromIndex === null) return;
                    e.preventDefault();
                    e.dataTransfer.dropEffect = 'move';
                    const rect = groupDiv.getBoundingClientRect();
                    const above = (e.clientY - rect.top) < rect.height / 2;
                    highlightZone(above ? index : index + 1);
                });
                groupDiv.addEventListener('drop', function(e) {
                    if (dragFromIndex === null) return;
                    e.preventDefault();
                    e.stopPropagation();
                    commitDrop();
                });

                body.appendChild(chips);
                body.appendChild(modeBar);
                body.appendChild(cfgArea);
                body.appendChild(subArea);
                body.appendChild(footerDiv);

                groupDiv.appendChild(headerDiv);
                groupDiv.appendChild(body);
                container.appendChild(groupDiv);

                container.appendChild(makeDropZone(index + 1));
            });

            updateAllCounts();
        }

        function moveGroup(index, direction) {
            const total = Object.keys(dataGroups).length;
            const target = index + direction;
            if (target < 0 || target >= total) return;
            moveGroupToPosition(index, direction === 1 ? target + 1 : target);
        }

        function moveGroupToPosition(from, position) {
            syncFromDOM();
            const names = Object.keys(dataGroups);
            if (from < 0 || from >= names.length) return;
            if (position < 0 || position > names.length) return;
            if (position === from || position === from + 1) { renderGroups(); return; }

            const moved = names.splice(from, 1)[0];
            const insertAt = position > from ? position - 1 : position;
            names.splice(insertAt, 0, moved);

            const reordered = {};
            names.forEach(n => { reordered[n] = dataGroups[n]; });
            dataGroups = reordered;
            markDirty(true);
            renderGroups();
        }

        function updateGroupName(inputElement) {
            const groupDiv = inputElement.closest('.server-group');
            const oldName = groupDiv.dataset.originalName;
            const newName = normalizeGroupKey(inputElement.value);
            if (!newName) {
                inputElement.value = oldName.replace(/_/g, ' ');
                updateAllCounts();
                return;
            }
            if (oldName !== newName) {
                if (Object.prototype.hasOwnProperty.call(dataGroups, newName)) {
                    showToast('A group with that name already exists.', 'err');
                    inputElement.value = oldName.replace(/_/g, ' ');
                    updateAllCounts();
                    return;
                }
                const rebuilt = {};
                for (const key of Object.keys(dataGroups)) {
                    if (key === oldName) rebuilt[newName] = dataGroups[oldName];
                    else rebuilt[key] = dataGroups[key];
                }
                dataGroups = rebuilt;
                groupDiv.dataset.originalName = newName;
                updateAllCounts();
                markDirty(true);
            }
        }

        function addNewGroup() {
            syncFromDOM();
            const uniqueId = 'New_Server_' + Math.floor(1000 + Math.random() * 9000);
            dataGroups[uniqueId] = { mode: 'configs', configs: [], subUrls: [], cachedSubConfigs: [] };
            markDirty(true);
            renderGroups();
            const els = document.querySelectorAll('.server-group');
            const last = els[els.length - 1];
            if (last) {
                last.scrollIntoView({ behavior: 'smooth', block: 'center' });
                const t = last.querySelector('.group-title');
                if (t) { t.focus(); t.select(); }
            }
        }

        function deleteGroup(groupName) {
            if (confirm('Delete this server group?')) {
                syncFromDOM();
                delete dataGroups[groupName];
                markDirty(true);
                renderGroups();
            }
        }

        async function regenerateSubToken() {
            if (!confirm('Generate a new 6-digit subscription code? Your old subscription link will stop working immediately.')) return;
            const btn = document.getElementById('regenTokenBtn');
            btn.disabled = true;
            btn.textContent = 'Generating…';
            try {
                const res = await fetch('/regenerate-token', { method: 'POST' });
                const data = await res.json();
                if (data && data.success && data.subToken) {
                    currentSubToken = data.subToken;
                    document.getElementById('subUrl').textContent = BASE_ORIGIN + '/sub/' + currentSubToken;
                    document.getElementById('subTokenBadge').textContent = 'code ' + currentSubToken;
                    showToast('New subscription code generated', 'ok');
                } else {
                    showToast('Failed to regenerate code.', 'err');
                }
            } catch (e) {
                showToast('Failed to regenerate code.', 'err');
            } finally {
                btn.disabled = false;
                btn.textContent = 'New code';
            }
        }

        function copySubLink() {
            const text = document.getElementById('subUrl').innerText;
            const done = function() {
                const btn = document.getElementById('copySubBtn');
                const orig = btn.textContent;
                btn.textContent = 'Copied!';
                showToast('Subscription link copied', 'ok');
                setTimeout(function() { btn.textContent = orig; }, 1600);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done, function() { showToast('Copy failed', 'err'); });
            } else {
                showToast('Copy not supported in this browser', 'err');
            }
        }

        async function saveAll() {
            syncFromDOM();
            const saveBtn = document.getElementById('saveAllBtn');
            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving…';
            try {
                const response = await fetch('/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ groups: dataGroups, rotationChunk: currentRotationChunk, subToken: currentSubToken, subTitle: currentSubTitle })
                });
                const result = await response.json();
                if (result.success) {
                    if (result.groups && typeof result.groups === 'object') dataGroups = result.groups;
                    markDirty(false);
                    renderGroups();
                    showToast('Saved successfully', 'ok');
                } else {
                    showToast('Error saving: ' + (result.error || 'unknown error'), 'err');
                }
            } catch (e) {
                showToast('Network error while saving.', 'err');
            } finally {
                saveBtn.disabled = false;
                saveBtn.innerHTML = SAVE_LABEL;
            }
        }

        const groupsContainerEl = document.getElementById('groupsContainer');
        groupsContainerEl.addEventListener('dragover', function(e) {
            if (dragFromIndex === null) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
        });
        groupsContainerEl.addEventListener('drop', function(e) {
            if (dragFromIndex === null) return;
            e.preventDefault();
            commitDrop();
        });

        window.addEventListener('dragover', function(e) {
            if (dragFromIndex === null) return;
            dragPointerX = e.clientX;
            dragPointerY = e.clientY;
            e.preventDefault();
        }, true);

        document.addEventListener('dragend', function() { clearDragState(); });
        window.addEventListener('drop', function(e) { if (dragFromIndex !== null) e.preventDefault(); });

        window.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                e.preventDefault();
                saveAll();
            }
        });
        window.addEventListener('beforeunload', function(e) {
            if (hasUnsavedChanges) { e.preventDefault(); e.returnValue = ''; }
        });

        document.getElementById('subTitleInput').value = currentSubTitle;
        updateChunkUI();
        renderGroups();
    </script>
</body>
</html>
  `;
}
