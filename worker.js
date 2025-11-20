// worker.js
// Bindings expected: MY_KV (users + sessions), PAGES_KV (static HTML pages)

addEventListener("fetch", event => {
  event.respondWith(handle(event.request));
});

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };

/* ------------------ helpers ------------------ */
function hex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,"0")).join("");
}
function randHex(lenBytes=16) {
  const a = new Uint8Array(lenBytes);
  crypto.getRandomValues(a);
  return hex(a);
}
async function sha256Hex(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return hex(buf);
}
function getCookieValue(cookieHeader="", name) {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (let p of parts) {
    const [k,v] = p.split("=").map(s=>s && s.trim());
    if (k === name) return v || "";
  }
  return null;
}
function makeCookieHeader(token, ttlSec=60*60*24*7) {
  // Secure + HttpOnly + Path=/ + Max-Age
  return `session=${token}; HttpOnly; Path=/; Max-Age=${ttlSec}; SameSite=Lax; Secure`;
}
function clearCookieHeader() {
  // expire immediately
  return `session=deleted; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`;
}
async function parseBodyFlexible(req) {
  const ct = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct === "application/json") {
    try { return await req.json(); } catch(e) { return {}; }
  }
  // browser form POST usually sends application/x-www-form-urlencoded
  if (ct === "application/x-www-form-urlencoded" || (req.method === "POST" && ct === "")) {
    try {
      const fd = await req.formData();
      const obj = {};
      for (const [k,v] of fd.entries()) obj[k] = v;
      return obj;
    } catch(e) {
      const t = await req.text().catch(()=>"");
      const p = new URLSearchParams(t);
      const obj = {};
      for (const [k,v] of p.entries()) obj[k] = v;
      return obj;
    }
  }
  // fallback try JSON
  try { return await req.json(); } catch(e){ return {}; }
}

/* ------------------ KV helpers ------------------ */
async function kvGet(key) {
  return await MY_KV.get(key);
}
async function kvPut(key, obj, opts) {
  const raw = typeof obj === "string" ? obj : JSON.stringify(obj);
  if (opts && opts.expirationTtl) {
    await MY_KV.put(key, raw, { expirationTtl: opts.expirationTtl });
  } else {
    await MY_KV.put(key, raw);
  }
}
async function kvDelete(key) {
  await MY_KV.delete(key);
}

/* ------------------ auth helpers ------------------ */
async function hashPassword(password, salt) {
  return await sha256Hex(salt + "|" + password);
}
async function sessionUsernameFromRequest(req) {
  const cookie = req.headers.get("Cookie") || "";
  const token = getCookieValue(cookie, "session");
  if (!token) return null;
  const raw = await kvGet(`sess:${token}`);
  if (!raw) return null;
  try {
    const sess = JSON.parse(raw);
    return sess.username;
  } catch(e) {
    return null;
  }
}
// return full session object (or null)
async function sessionFromRequest(req) {
  const cookie = req.headers.get("Cookie") || "";
  const token = getCookieValue(cookie, "session");
  if (!token) return null;
  const raw = await kvGet(`sess:${token}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch(e) { return null; }
}

/* ------------------ page serving with injection ------------------ */
async function servePageFromPagesKV(key, req) {
  const raw = await PAGES_KV.get(key);
  if (!raw) return new Response("Not found", { status:404 });

  // Dashboard: inject username (require login)
  if (key === "dashboard.html") {
    const username = await sessionUsernameFromRequest(req);
    if (!username) return new Response(null, { status: 303, headers: { "Location": "/login" }});
    const userRaw = await MY_KV.get(`user:${username}`);
    if (!userRaw) return new Response(null, { status: 303, headers: { "Location": "/login" }});
    let u;
    try { u = JSON.parse(userRaw); } catch(e){ u = { username }; }
    const display = u.displayName || u.username || username;
    const safe = escapeHtml(display);
    const html = String(raw).split("{{USERNAME}}").join(safe);
    return new Response(html, { status:200, headers: { "Content-Type": "text/html; charset=utf-8" }});
  }

  // Admin: require admin role, inject username
  if (key === "admin.html") {
    const sess = await sessionFromRequest(req);
    if (!sess || !sess.username) return new Response(null, { status: 303, headers: { "Location": "/login" }});
    const rawUser = await MY_KV.get(`user:${sess.username}`);
    if (!rawUser) return new Response(null, { status: 303, headers: { "Location": "/login" }});
    let user;
    try { user = JSON.parse(rawUser); } catch(e){ user = null; }
    if (!user || user.role !== 'admin') return new Response("Forbidden", { status:403 });
    const display = user.displayName || user.username || sess.username;
    const safe = escapeHtml(display);
    const html = String(raw).split("{{USERNAME}}").join(safe);
    return new Response(html, { status:200, headers: { "Content-Type": "text/html; charset=utf-8" }});
  }

  // other pages
  return new Response(raw, { status:200, headers: { "Content-Type": guessContentType(key) }});
}
function guessContentType(key) {
  if (key.endsWith(".html")) return "text/html; charset=utf-8";
  if (key.endsWith(".css")) return "text/css; charset=utf-8";
  if (key.endsWith(".js")) return "application/javascript; charset=utf-8";
  return "text/plain; charset=utf-8";
}
function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#39;");
}

/* ------------------ API handlers ------------------ */

async function handleRegister(req) {
  const body = await parseBodyFlexible(req);

  const rawName = (body.username || "").trim();
  const username = rawName.toLowerCase();
  const displayName = (body.displayName || body.name || rawName || username).trim();
  const whatsapp = (body.whatsapp || body.wa || "").trim();
  const password = body.password || "";

  if (!username || !/^[a-z0-9_.-]{3,40}$/.test(username)) {
    return new Response(JSON.stringify({ error:"invalid_username" }), { status:400, headers: JSON_HEADERS });
  }
  if (!/^[0-9+\- ]{6,20}$/.test(whatsapp)) {
    return new Response(JSON.stringify({ error:"invalid_whatsapp" }), { status:400, headers: JSON_HEADERS });
  }
  if (!password || password.length < 6) {
    return new Response(JSON.stringify({ error:"weak_password" }), { status:400, headers: JSON_HEADERS });
  }

  const exists = await kvGet(`user:${username}`);
  if (exists) return new Response(JSON.stringify({ error:"user_exists" }), { status:409, headers: JSON_HEADERS });

  const salt = randHex(16);
  const passwordHash = await hashPassword(password, salt);
  // role: default 'user', allow explicit admin creation only if request sets role:'admin' or username === 'admin'
  const role = (body.role === 'admin' || username === 'admin') ? 'admin' : 'user';
  const user = { username, displayName, whatsapp, salt, passwordHash, role, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session token and include role in session
  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, role, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const accept = (req.headers.get("Accept") || "");
  const contentType = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  const isForm = contentType === "application/x-www-form-urlencoded";

  if (isForm && accept.includes("text/html")) {
    return new Response(null, { status:303, headers: { "Set-Cookie": makeCookieHeader(token, ttl), "Location": "/login?registered=1" }});
  }
  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: Object.assign({}, JSON_HEADERS, { "Set-Cookie": makeCookieHeader(token, ttl) })});
}

async function handleLogin(req) {
  const body = await parseBodyFlexible(req);
  const rawName = (body.username || "").trim();
  const username = rawName.toLowerCase();
  const password = body.password || "";

  if (!username || !password) return new Response(JSON.stringify({ error:"missing" }), { status:400, headers: JSON_HEADERS });

  const raw = await kvGet(`user:${username}`);
  if (!raw) {
    const contentType = (req.headers.get("Content-Type") || "").split(";")[0].trim();
    const isForm = contentType === "application/x-www-form-urlencoded";
    if (isForm) return new Response(null, { status:303, headers: { "Location": "/login?error=invalid_credentials" }});
    return new Response(JSON.stringify({ error:"invalid_credentials" }), { status:401, headers: JSON_HEADERS });
  }

  let user;
  try { user = JSON.parse(raw); } catch(e) { user = null; }
  if (!user || !user.salt || !user.passwordHash) {
    return new Response(JSON.stringify({ error:"invalid_credentials" }), { status:401, headers: JSON_HEADERS });
  }

  const computed = await hashPassword(password, user.salt);
  if (computed !== user.passwordHash) {
    const contentType = (req.headers.get("Content-Type") || "").split(";")[0].trim();
    const isForm = contentType === "application/x-www-form-urlencoded";
    if (isForm) return new Response(null, { status:303, headers: { "Location": "/login?error=invalid_credentials" }});
    return new Response(JSON.stringify({ error:"invalid_credentials" }), { status:401, headers: JSON_HEADERS });
  }

  // success -> create session token & cookie (include role in session)
  const token = randHex(32);
  const ttl = 60*60*24*7;
  const role = user.role || 'user';
  await kvPut(`sess:${token}`, { username, role, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const accept = (req.headers.get("Accept") || "");
  const contentType = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  const isForm = contentType === "application/x-www-form-urlencoded";

  const redirectTarget = (user && user.role === 'admin') ? "/admin" : "/dashboard";

  if (isForm && accept.includes("text/html")) {
    return new Response(null, { status:303, headers: { "Set-Cookie": makeCookieHeader(token, ttl), "Location": redirectTarget }});
  }

  return new Response(JSON.stringify({ ok:true, token, role }), { status:200, headers: Object.assign({}, JSON_HEADERS, { "Set-Cookie": makeCookieHeader(token, ttl) })});
}

async function handleLogout(req) {
  const cookie = req.headers.get("Cookie") || "";
  const token = getCookieValue(cookie, "session");
  if (token) {
    await kvDelete(`sess:${token}`);
  }
  return new Response(null, { status:303, headers: { "Set-Cookie": clearCookieHeader(), "Location": "/login" }});
}

async function handleMe(req) {
  const username = await sessionUsernameFromRequest(req);
  if (!username) return new Response(JSON.stringify({ error:"no_session" }), { status:401, headers: JSON_HEADERS });
  const raw = await kvGet(`user:${username}`);
  if (!raw) return new Response(JSON.stringify({ error:"not_found" }), { status:404, headers: JSON_HEADERS });
  const u = JSON.parse(raw);
  delete u.passwordHash; delete u.salt;
  return new Response(JSON.stringify({ ok:true, user: u }), { status:200, headers: JSON_HEADERS });
}

/* ------------------ admin handlers ------------------ */

// list users (admin only)
async function handleAdminList(req) {
  const sess = await sessionFromRequest(req);
  if (!sess || !sess.username) return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });
  const rawUser = await kvGet(`user:${sess.username}`);
  if (!rawUser) return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });
  let adminUser;
  try { adminUser = JSON.parse(rawUser); } catch(e){ adminUser = null; }
  if (!adminUser || adminUser.role !== 'admin') return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });

  const list = await MY_KV.list({ prefix: 'user:' });
  const users = [];
  for (const k of list.keys) {
    const raw = await MY_KV.get(k.name);
    if (!raw) continue;
    try {
      const u = JSON.parse(raw);
      delete u.passwordHash;
      delete u.salt;
      users.push(u);
    } catch(e){}
  }
  return new Response(JSON.stringify({ ok:true, users }), { status:200, headers: JSON_HEADERS });
}

// delete user (admin only)
async function handleAdminDelete(req) {
  const sess = await sessionFromRequest(req);
  if (!sess || !sess.username) return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });
  const rawUser = await kvGet(`user:${sess.username}`);
  if (!rawUser) return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });
  let adminUser;
  try { adminUser = JSON.parse(rawUser); } catch(e){ adminUser = null; }
  if (!adminUser || adminUser.role !== 'admin') return new Response(JSON.stringify({ error:'unauthorized' }), { status:401, headers: JSON_HEADERS });

  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim().toLowerCase();
  if (!username) return new Response(JSON.stringify({ error:'missing_username' }), { status:400, headers: JSON_HEADERS });

  // prevent deleting the last admin? (not implemented) - you can add checks if needed

  await kvDelete(`user:${username}`);

  const sessions = await MY_KV.list({ prefix: 'sess:' });
  for (const s of sessions.keys) {
    const raw = await MY_KV.get(s.name);
    if (!raw) continue;
    try {
      const obj = JSON.parse(raw);
      if (obj.username === username) {
        await MY_KV.delete(s.name);
      }
    } catch(e){}
  }

  return new Response(JSON.stringify({ ok:true }), { status:200, headers: JSON_HEADERS });
}

/* ------------------ main handler ------------------ */
async function handle(req) {
  const url = new URL(req.url);

  // API routes
  if (url.pathname === "/api/register" && req.method === "POST") return handleRegister(req);
  if (url.pathname === "/api/login" && req.method === "POST") return handleLogin(req);
  if (url.pathname === "/api/logout" && (req.method === "POST" || req.method === "GET")) return handleLogout(req);
  if (url.pathname === "/api/me" && req.method === "GET") return handleMe(req);

  // admin API
  if (url.pathname === "/api/admin/users" && req.method === "GET") return handleAdminList(req);
  if (url.pathname === "/api/admin/delete" && (req.method === "POST" || req.method === "DELETE")) return handleAdminDelete(req);

  // static pages from PAGES_KV
  const mapping = {
    "/": "index.html",
    "/index.html": "index.html",
    "/login": "login.html",
    "/login.html": "login.html",
    "/register": "register.html",
    "/register.html": "register.html",
    "/dashboard": "dashboard.html",
    "/dashboard.html": "dashboard.html",
    "/admin": "admin.html",
    "/admin.html": "admin.html"
  };

  if (mapping[url.pathname]) {
    return await servePageFromPagesKV(mapping[url.pathname], req);
  }

  // fallback: try the path without leading slash as key
  const key = url.pathname.startsWith("/") ? url.pathname.slice(1) : url.pathname;
  if (key) {
    const raw = await PAGES_KV.get(key);
    if (raw) {
      if (key === "dashboard.html") return await servePageFromPagesKV("dashboard.html", req);
      if (key === "admin.html") return await servePageFromPagesKV("admin.html", req);
      return new Response(raw, { status:200, headers:{ "Content-Type": guessContentType(key) }});
    }
  }

  return new Response("Not found", { status:404 });
}
