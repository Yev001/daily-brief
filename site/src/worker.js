// Daily brief — a small phone-first checklist site on Cloudflare Workers + D1.
// Public source: contains no secrets and no personal data. Secrets are Worker
// secrets (SHA-256 hashes only): API_TOKEN_SHA256, LOGIN_KEY_SHA256.
// Optional vars for Cloudflare Access: ACCESS_TEAM_DOMAIN, ACCESS_AUD, ALLOWED_EMAIL.

const SECTIONS = [
  { key: "questions", emoji: "❓", title: "Questions", owner: "Director" },
  { key: "weather", emoji: "🌤️", title: "Weather", owner: "Director" },
  { key: "today", emoji: "📅", title: "Today", owner: "Director" },
  { key: "tomorrow", emoji: "🔜", title: "Tomorrow", owner: "Director" },
  { key: "waiting", emoji: "📝", title: "Waiting on you", owner: "Director" },
  { key: "watching", emoji: "👀", title: "Watching", owner: "Director" },
  { key: "school", emoji: "🎓", title: "School", owner: "School Bot" },
  { key: "health", emoji: "🩺", title: "Health", owner: "GP Bot" },
  { key: "shopping", emoji: "🛍️", title: "Shopping & deliveries", owner: "Jarvis" },
  { key: "work", emoji: "💼", title: "Work", owner: "Work Bot" },
  { key: "projects", emoji: "📁", title: "Projects", owner: "Director" },
  { key: "travel", emoji: "✈️", title: "Travel", owner: "Holiday Bot" },
];
const SECTION_KEYS = new Set(SECTIONS.map((s) => s.key));
const KINDS = new Set(["task", "text", "heading", "question", "project"]);
const CHECKABLE = new Set(["task", "question", "project"]);
const TZ = "Europe/London";
const COOKIE = "db_sid";
const SESSION_DAYS = 365;
const MAX_BODY = 256 * 1024;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) return await handleApi(request, env, url);
      if (url.pathname === "/login") return await handleLogin(request, env, url);
      if (url.pathname === "/logout") return await handleLogout(request, env);
      if (url.pathname === "/robots.txt") return text("User-agent: *\nDisallow: /\n");
      if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
      const who = await humanAuth(request, env);
      if (!who) return lockedPage();
      if (url.pathname.startsWith("/ui/")) return await handleUi(request, env, url);
      if (url.pathname === "/" && request.method === "GET") return await renderPage(env);
      return json({ error: "not found" }, 404);
    } catch (err) {
      console.error(JSON.stringify({ msg: "unhandled", path: url.pathname, error: String(err && err.stack || err) }));
      return json({ error: "internal error" }, 500);
    }
  },
};

// ---------- auth ----------
async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function matchesHash(value, expectedHex) {
  if (!value || !expectedHex) return false;
  const a = new TextEncoder().encode(await sha256Hex(value));
  const b = new TextEncoder().encode(String(expectedHex).trim().toLowerCase());
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}
async function botAuth(request, env) {
  const h = request.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? matchesHash(m[1].trim(), env.API_TOKEN_SHA256) : false;
}
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  for (const part of c.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return null;
}
async function humanAuth(request, env) {
  const sid = getCookie(request, COOKIE);
  if (sid) {
    const row = await env.DB.prepare("SELECT expires_at FROM sessions WHERE id_hash = ?").bind(await sha256Hex(sid)).first();
    if (row && row.expires_at > Date.now()) return "session";
  }
  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (jwt && env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) {
    const email = await verifyAccessJwt(jwt, env);
    if (email) return "access:" + email;
  }
  return null;
}
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function verifyAccessJwt(token, env) {
  try {
    const [h, p, sig] = token.split(".");
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
    const team = String(env.ACCESS_TEAM_DOMAIN).replace(/^https?:\/\//, "").replace(/\/$/, "");
    const certs = await (await fetch(`https://${team}/cdn-cgi/access/certs`, { cf: { cacheTtl: 3600 } })).json();
    const jwk = (certs.keys || []).find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(sig), new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return null;
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(env.ACCESS_AUD)) return null;
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    if (payload.iss && payload.iss !== `https://${team}`) return null;
    const email = String(payload.email || "").toLowerCase();
    if (env.ALLOWED_EMAIL && email !== String(env.ALLOWED_EMAIL).toLowerCase()) return null;
    return email || null;
  } catch (e) {
    console.warn(JSON.stringify({ msg: "access jwt rejected", error: String(e) }));
    return null;
  }
}
async function handleLogin(request, env, url) {
  const k = url.searchParams.get("k");
  if (!(await matchesHash(k, env.LOGIN_KEY_SHA256))) {
    console.warn(JSON.stringify({ msg: "bad login attempt" }));
    return lockedPage(403);
  }
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const sid = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const expires = Date.now() + SESSION_DAYS * 86400000;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()),
    env.DB.prepare("INSERT INTO sessions (id_hash, expires_at) VALUES (?, ?)").bind(await sha256Hex(sid), expires),
  ]);
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": `${COOKIE}=${sid}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}
async function handleLogout(request, env) {
  const sid = getCookie(request, COOKIE);
  if (sid) await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(await sha256Hex(sid)).run();
  return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
}

// ---------- data ----------
async function loadSections(env) {
  const { results } = await env.DB.prepare("SELECT key, data, updated_at FROM sections").all();
  const byKey = Object.fromEntries(results.map((r) => [r.key, r]));
  return SECTIONS.map((s) => {
    const row = byKey[s.key];
    const data = row ? JSON.parse(row.data) : { items: [] };
    return { ...s, label: data.label || null, note: data.note || null, image: data.image || null, items: data.items || [], updated_at: row ? row.updated_at : null, _raw: row ? row.updated_at : null };
  });
}
function publicSection(s) {
  const { _raw, ...rest } = s;
  return rest;
}
function londonParts(date) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, weekday: "long", day: "numeric", month: "long", year: "numeric" }).formatToParts(date);
  const o = Object.fromEntries(parts.map((p) => [p.type, p.value]));
  return o;
}
function briefTitle(now = new Date()) {
  const o = londonParts(now);
  return `☀️ Daily brief: ${o.weekday} ${o.day} ${o.month}`;
}
function tomorrowLabel(now = new Date()) {
  const t = new Date(now.getTime() + 86400000);
  const s = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, weekday: "short", day: "numeric", month: "short" }).formatToParts(t);
  const o = Object.fromEntries(s.map((p) => [p.type, p.value]));
  return `Tomorrow (${o.weekday} ${o.day} ${o.month})`;
}
async function getBrief(env) {
  const sections = await loadSections(env);
  return { title: briefTitle(), generated_at: new Date().toISOString(), sections: sections.map(publicSection) };
}
function walk(items, fn, parent = null) {
  for (const it of items || []) {
    fn(it, parent);
    if (it.sub) walk(it.sub, fn, it);
  }
}
function cleanId(id) {
  if (id === undefined || id === null || id === "") return null;
  const s = String(id).trim();
  if (!/^[A-Za-z0-9_.:-]{1,80}$/.test(s)) throw new HttpError(400, `bad item id: ${s.slice(0, 40)}`);
  return s;
}
function cleanLink(l) {
  if (!l) return null;
  const s = String(l).trim();
  return /^https?:\/\/\S+$/i.test(s) ? s.slice(0, 2000) : null;
}
function normItems(items, key, prevMap, depth, seen, now) {
  if (!Array.isArray(items)) throw new HttpError(400, "items must be an array");
  return items.map((raw) => {
    const it = typeof raw === "string" ? { text: raw } : raw || {};
    let id = cleanId(it.id);
    if (!id) id = `${key}-${crypto.randomUUID().slice(0, 8)}`;
    if (seen.has(id)) throw new HttpError(400, `duplicate item id: ${id}`);
    seen.add(id);
    const kind = KINDS.has(it.kind) ? it.kind : "task";
    const out = { id, kind, text: String(it.text ?? "").slice(0, 4000) };
    const indent = parseInt(it.indent, 10);
    if (indent > 0) out.indent = Math.min(indent, 4);
    const link = cleanLink(it.link);
    if (link) out.link = link;
    if (CHECKABLE.has(kind)) {
      out.checked = !!it.checked;
      const prev = prevMap.get(id);
      out.checked_at = out.checked ? (it.checked_at || (prev && prev.checked && prev.checked_at) || now) : null;
    }
    if (Array.isArray(it.sub) && it.sub.length) {
      if (depth >= 3) throw new HttpError(400, "sub-items nested too deep");
      out.sub = normItems(it.sub, key, prevMap, depth + 1, seen, now);
    }
    return out;
  });
}
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function putSection(env, key, body) {
  if (!SECTION_KEYS.has(key)) throw new HttpError(404, `unknown section: ${key}`);
  const payload = Array.isArray(body) ? { items: body } : body || {};
  const row = await env.DB.prepare("SELECT data FROM sections WHERE key = ?").bind(key).first();
  const prev = row ? JSON.parse(row.data) : { items: [] };
  const prevMap = new Map();
  walk(prev.items, (it) => prevMap.set(it.id, it));
  // ids must be unique across the whole brief
  const others = new Set();
  const { results } = await env.DB.prepare("SELECT key, data FROM sections WHERE key != ?").bind(key).all();
  for (const r of results) walk(JSON.parse(r.data).items, (it) => others.add(it.id));
  const now = new Date().toISOString();
  const seen = new Set();
  const items = normItems(payload.items || [], key, prevMap, 0, seen, now);
  for (const id of seen) if (others.has(id)) throw new HttpError(409, `item id already used in another section: ${id}`);
  const data = { items };
  for (const f of ["label", "note"]) {
    const v = f in payload ? payload[f] : prev[f];
    if (v) data[f] = String(v).slice(0, 500);
  }
  const img = "image" in payload ? cleanLink(payload.image) : prev.image;
  if (img) data.image = img;
  await env.DB.prepare("INSERT INTO sections (key, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at")
    .bind(key, JSON.stringify(data), now).run();
  console.log(JSON.stringify({ msg: "section replaced", key, items: seen.size }));
  return { key, ...data, updated_at: now };
}

async function setChecked(env, id, checked) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const { results } = await env.DB.prepare("SELECT key, data, updated_at FROM sections").all();
    for (const r of results) {
      const data = JSON.parse(r.data);
      let found = null;
      walk(data.items, (it) => { if (it.id === id) found = it; });
      if (!found) continue;
      if (!CHECKABLE.has(found.kind || "task")) throw new HttpError(400, "item has no tickbox");
      const now = new Date().toISOString();
      if (!!found.checked !== checked) {
        found.checked = checked;
        found.checked_at = checked ? now : null;
      }
      const res = await env.DB.prepare("UPDATE sections SET data = ?, updated_at = ? WHERE key = ? AND updated_at = ?")
        .bind(JSON.stringify(data), now, r.key, r.updated_at).run();
      if (res.meta.changes === 1) {
        console.log(JSON.stringify({ msg: "item checked", id, checked, section: r.key }));
        return { id, section: r.key, checked: found.checked, checked_at: found.checked_at };
      }
      break; // concurrent write: retry
    }
    if (attempt === 0) {
      // not found in any section?
      let exists = false;
      for (const r of results) walk(JSON.parse(r.data).items, (it) => { if (it.id === id) exists = true; });
      if (!exists) throw new HttpError(404, `no item with id ${id}`);
    }
  }
  throw new HttpError(409, "busy, try again");
}

async function readJson(request) {
  const len = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (len > MAX_BODY) throw new HttpError(413, "body too large");
  const t = await request.text();
  if (t.length > MAX_BODY) throw new HttpError(413, "body too large");
  if (!t.trim()) return {};
  try { return JSON.parse(t); } catch { throw new HttpError(400, "invalid JSON"); }
}
function wantChecked(url, body) {
  const q = url.searchParams.get("checked");
  if (q !== null) return !/^(0|false|no)$/i.test(q);
  if (body && "checked" in body) return !!body.checked;
  return true;
}

// ---------- routes ----------
async function handleApi(request, env, url) {
  if (!(await botAuth(request, env))) return json({ error: "unauthorized" }, 401, { "WWW-Authenticate": "Bearer" });
  try {
    const p = url.pathname;
    if (p === "/api/brief" && request.method === "GET") return json(await getBrief(env));
    let m = p.match(/^\/api\/section\/([a-z]+)$/);
    if (m) {
      if (request.method === "GET") {
        const s = (await getBrief(env)).sections.find((x) => x.key === m[1]);
        return s ? json(s) : json({ error: "unknown section" }, 404);
      }
      if (request.method === "PUT") return json(await putSection(env, m[1], await readJson(request)));
    }
    m = p.match(/^\/api\/item\/([A-Za-z0-9_.:-]{1,80})\/check$/);
    if (m && request.method === "POST") {
      const body = await readJson(request);
      return json(await setChecked(env, m[1], wantChecked(url, body)));
    }
    return json({ error: "not found" }, 404);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    throw e;
  }
}
async function handleUi(request, env, url) {
  try {
    if (url.pathname === "/ui/version" && request.method === "GET") {
      const r = await env.DB.prepare("SELECT MAX(updated_at) AS v FROM sections").first();
      return json({ version: (r && r.v) || null });
    }
    const m = url.pathname.match(/^\/ui\/item\/([A-Za-z0-9_.:-]{1,80})\/check$/);
    if (m && request.method === "POST") {
      const origin = request.headers.get("Origin");
      if (origin && origin !== url.origin) return json({ error: "bad origin" }, 403);
      const body = await readJson(request);
      return json(await setChecked(env, m[1], wantChecked(url, body)));
    }
    return json({ error: "not found" }, 404);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    throw e;
  }
}

// ---------- rendering ----------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function md(s) {
  let h = esc(s);
  h = h.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  h = h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  h = h.replace(/~~(.+?)~~/g, "$1");
  h = h.replace(/(^|[\s(])\*(?!\s)(.+?)\*(?=[\s).,;:!?]|$)/g, "$1<em>$2</em>");
  return h;
}
function renderItem(it, depth = 0) {
  const ind = (it.indent || 0) + depth;
  const style = ind ? ` style="--ind:${ind}"` : "";
  const link = it.link ? ` <a class="ext" href="${esc(it.link)}" target="_blank" rel="noopener noreferrer" aria-label="Open link">↗</a>` : "";
  const kind = it.kind || "task";
  let sub = "";
  if (it.sub && it.sub.length) sub = it.sub.map((c) => renderItem(c, depth + 1)).join("");
  if (kind === "project") {
    const open = it.checked ? "" : "";
    return `<details class="project${it.checked ? " done" : ""}"${style}${open}><summary><span class="ptitle">${md(it.text)}</span></summary>
      ${checkRow({ ...it, text: "Archive?", kind: "task", link: null }, 0, true)}
      <div class="pbody">${sub}</div></details>`;
  }
  if (kind === "heading") return `<div class="line heading"${style}>${md(it.text)}${link}</div>${sub}`;
  if (kind === "text") return `<div class="line text"${style}><span class="dot" aria-hidden="true">•</span><span>${md(it.text)}${link}</span></div>${sub}`;
  return checkRow(it, depth, false) + sub;
}
function checkRow(it, depth, isArchive) {
  const ind = (it.indent || 0) + depth;
  const style = ind ? ` style="--ind:${ind}"` : "";
  const cid = `cb-${esc(it.id)}`;
  const link = it.link ? ` <a class="ext" href="${esc(it.link)}" target="_blank" rel="noopener noreferrer" aria-label="Open link">↗</a>` : "";
  return `<div class="row${it.checked ? " checked" : ""}${isArchive ? " archive" : ""}${it.kind === "question" ? " question" : ""}"${style}>
    <input type="checkbox" id="${cid}" data-id="${esc(it.id)}"${it.checked ? " checked" : ""}>
    <label for="${cid}">${md(it.text)}</label>${link}</div>`;
}
async function renderPage(env) {
  const brief = await getBrief(env);
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const version = brief.sections.reduce((m, s) => (s.updated_at && s.updated_at > m ? s.updated_at : m), "");
  const body = brief.sections.map((s) => {
    const heading = s.key === "tomorrow" ? (s.label || tomorrowLabel()) : (s.label || s.title);
    const empty = !s.items.length && !s.image ? `<div class="line text muted">Nothing here</div>` : "";
    const img = s.image ? `<img class="wx" src="${esc(s.image)}" alt="Weather chart" loading="lazy">` : "";
    const note = s.note ? `<p class="note">${md(s.note)}</p>` : "";
    return `<section id="${s.key}"><h2><span class="emoji">${s.emoji}</span> ${esc(heading)}<span class="owner">${esc(s.owner)}</span></h2>${note}${img}${s.items.map((i) => renderItem(i)).join("")}${empty}</section>`;
  }).join("\n");
  const html = `<!doctype html><html lang="en-GB"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow"><meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f6f5f2" media="(prefers-color-scheme: light)"><meta name="theme-color" content="#16181c" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes"><title>${esc(brief.title)}</title>
<style nonce="${nonce}">${CSS}</style></head><body>
<header><h1>${esc(brief.title)}</h1></header>
<nav>${brief.sections.map((s) => `<a href="#${s.key}">${s.emoji}</a>`).join("")}</nav>
<main>${body}</main>
<footer>Each bot keeps its own section up to date. Ticked items stay until the bot clears them. <a href="/logout">Log out</a></footer>
<div id="toast" role="status" aria-live="polite"></div>
<script nonce="${nonce}">const VERSION=${JSON.stringify(version)};${JS}</script></body></html>`;
  return new Response(html, { headers: htmlHeaders(nonce) });
}
function htmlHeaders(nonce) {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": `default-src 'none'; img-src https: data:; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  };
}
function lockedPage(status = 401) {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><meta name="color-scheme" content="light dark"><title>Daily brief</title><style nonce="${nonce}">${CSS}</style></head><body><main class="locked"><h1>🔒 Daily brief</h1><p>This page is private. Open your personal login link to sign in on this device.</p></main></body></html>`;
  return new Response(html, { status, headers: htmlHeaders(nonce) });
}
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex", ...extra } });
}
function text(t) {
  return new Response(t, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

const CSS = `
:root{--bg:#f6f5f2;--card:#fff;--fg:#1b1d21;--muted:#6b7078;--line:#e6e3dc;--accent:#2f6fed;--done:#9aa0a8;--chip:#efece6}
@media (prefers-color-scheme: dark){:root{--bg:#16181c;--card:#1f2228;--fg:#eceef1;--muted:#9aa1ab;--line:#2c3038;--accent:#7aa7ff;--done:#6c727c;--chip:#2a2e35}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)}
header{padding:18px 16px 4px}h1{font-size:24px;margin:0;line-height:1.25}
nav{position:sticky;top:0;z-index:5;display:flex;gap:4px;overflow-x:auto;padding:8px 12px;background:var(--bg);border-bottom:1px solid var(--line);scrollbar-width:none}
nav a{flex:0 0 auto;text-decoration:none;font-size:22px;min-width:44px;height:44px;display:flex;align-items:center;justify-content:center;border-radius:12px;background:var(--chip)}
main{max-width:760px;margin:0 auto;padding:8px 10px 24px}
section{background:var(--card);border:1px solid var(--line);border-radius:16px;margin:12px 0;padding:6px 8px 10px;scroll-margin-top:70px}
h2{font-size:19px;margin:8px 6px 6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.owner{margin-left:auto;font-size:12px;font-weight:500;color:var(--muted);background:var(--chip);padding:2px 8px;border-radius:999px}
.note{margin:2px 8px 6px;color:var(--muted);font-size:14px;font-style:italic}
.row{display:flex;align-items:flex-start;gap:4px;padding-left:calc(var(--ind,0) * 22px);border-top:1px solid var(--line)}
section>.row:first-of-type{border-top:0}
.row input{flex:0 0 auto;appearance:none;-webkit-appearance:none;width:28px;height:28px;margin:10px 8px 10px 6px;border:2px solid var(--muted);border-radius:8px;background:transparent;display:grid;place-content:center;cursor:pointer}
.row input::before{content:"";width:14px;height:8px;border-left:3px solid #fff;border-bottom:3px solid #fff;transform:translateY(-2px) rotate(-45deg) scale(0);transition:transform .12s}
.row input:checked{background:var(--accent);border-color:var(--accent)}
.row input:checked::before{transform:translateY(-2px) rotate(-45deg) scale(1)}
.row input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.row label{flex:1;min-height:48px;padding:11px 6px 11px 0;cursor:pointer;word-break:break-word;-webkit-tap-highlight-color:transparent}
.row.checked>label{text-decoration:line-through;color:var(--done)}
.row.pending{opacity:.6}
.row.question>label{font-weight:600}
.ext{flex:0 0 auto;text-decoration:none;color:var(--accent);font-size:18px;padding:11px 8px;min-width:44px;text-align:center}
a{color:var(--accent)}
.line{padding:6px 8px 6px calc(8px + var(--ind,0) * 22px);word-break:break-word}
.line.text{display:flex;gap:8px}.dot{color:var(--muted)}
.line.heading{font-weight:700;padding-top:12px}
.muted{color:var(--muted)}
.wx{display:block;width:100%;height:auto;border-radius:10px;margin:4px 0 6px;background:var(--chip)}
details.project{border:1px solid var(--line);border-radius:12px;margin:8px 2px;padding:0 4px 4px}
details.project>summary{list-style:none;cursor:pointer;padding:12px 8px;font-weight:700;font-size:17px;min-height:48px;display:flex;align-items:center;gap:8px}
details.project>summary::-webkit-details-marker{display:none}
details.project>summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details.project[open]>summary::before{transform:rotate(90deg)}
details.project.done>summary .ptitle{text-decoration:line-through;color:var(--done)}
.row.archive{border-top:1px solid var(--line)}
.pbody .row{border-top:0}
footer{max-width:760px;margin:0 auto;padding:4px 18px 32px;color:var(--muted);font-size:13px}
#toast{position:fixed;left:50%;bottom:calc(16px + env(safe-area-inset-bottom));transform:translateX(-50%);background:#c0392b;color:#fff;padding:10px 16px;border-radius:12px;font-size:15px;display:none;max-width:90vw}
.locked{max-width:480px;margin:18vh auto;padding:24px;text-align:center}
`;

const JS = `
const toast=document.getElementById('toast');
function showToast(m){toast.textContent=m;toast.style.display='block';clearTimeout(showToast.t);showToast.t=setTimeout(()=>toast.style.display='none',3500);}
document.addEventListener('change',async(e)=>{
  const cb=e.target; if(!cb.matches('input[type=checkbox][data-id]'))return;
  const row=cb.closest('.row'); const want=cb.checked;
  row.classList.toggle('checked',want); row.classList.add('pending');
  const proj=cb.closest('details.project'); if(proj&&row.classList.contains('archive'))proj.classList.toggle('done',want);
  try{
    const r=await fetch('/ui/item/'+encodeURIComponent(cb.dataset.id)+'/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({checked:want}),credentials:'same-origin'});
    if(!r.ok)throw new Error(r.status===401?'Signed out — open your login link again':'Could not save ('+r.status+')');
  }catch(err){cb.checked=!want;row.classList.toggle('checked',!want);if(proj&&row.classList.contains('archive'))proj.classList.toggle('done',!want);showToast(err.message||'Could not save, check your connection');}
  finally{row.classList.remove('pending');}
});
document.addEventListener('visibilitychange',async()=>{
  if(document.visibilityState!=='visible')return;
  try{const r=await fetch('/ui/version',{credentials:'same-origin'});if(r.ok){const j=await r.json();if(j.version&&j.version!==VERSION&&!document.querySelector('.row.pending')){const y=scrollY;sessionStorage.setItem('y',y);location.reload();}}}catch{}
});
const y=sessionStorage.getItem('y');if(y){sessionStorage.removeItem('y');scrollTo(0,+y);}
`;
