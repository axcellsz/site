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
  if (ct === "application/x-www-form-urlencoded" || req.method === "POST" && ct === "") {
    // form submission from browser (no JS) => parse formData
    try {
      const fd = await req.formData();
      const obj = {};
      for (const [k,v] of fd.entries()) obj[k] = v;
      return obj;
    } catch(e) {
      // fallback: try text -> urlsearchparams
      const t = await req.text().catch(()=>"");
      const p = new URLSearchParams(t);
      const obj = {};
      for (const [k,v] of p.entries()) obj[k] = v;
      return obj;
    }
  }
  // fallback: attempt JSON
  try { return await req.json(); } catch(e){ return {}; }
}

/* ------------------ KV helpers ------------------ */
async function kvGet(key) {
  const v = await MY_KV.get(key);
  return v;
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
  // simple salted SHA-256 (ok for demo). salt must be random hex.
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

/* ------------------ page serving with injection ------------------ */
async function servePageFromPagesKV(key, req) {
  // key like 'dashboard.html' or 'login.html'
  const raw = await PAGES_KV.get(key);
  if (!raw) return new Response("Not found", { status:404 });
  if (key === "dashboard.html") {
    // require session
    const username = await sessionUsernameFromRequest(req);
    if (!username) {
      // redirect to login if not logged in
      return new Response(null, { status: 303, headers: { "Location": "/login" }});
    }
    // personalize by replacing placeholder {{USERNAME}} (safe-escaped)
    const safe = escapeHtml(username);
    const html = raw.replace("{{USERNAME}}", safe);
    return new Response(html, { status:200, headers: { "Content-Type": "text/html; charset=utf-8" }});
  }
  // other pages: return raw
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
  const username = (body.username || "").trim();
  const whatsapp = (body.whatsapp || body.wa || "").trim();
  const password = body.password || "";
  if (!username || !/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) {
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
  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session and set cookie then redirect to login page (form POST)
  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  if (isForm && accept.includes("text/html")) {
    // redirect to login page (we created session but user must login)
    return new Response(null, { status:303, headers: { "Set-Cookie": makeCookieHeader(token, ttl), "Location": "/login?registered=1" }});
  }
  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: Object.assign({}, JSON_HEADERS, { "Set-Cookie": makeCookieHeader(token, ttl) })});
}

async function handleLogin(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim();
  const password = body.password || "";
  if (!username || !password) return new Response(JSON.stringify({ error:"missing" }), { status:400, headers: JSON_HEADERS });
  const raw = await kvGet(`user:${username}`);
  if (!raw) return new Response(JSON.stringify({ error:"invalid_credentials" }), { status:401, headers: JSON_HEADERS });
  const user = JSON.parse(raw);
  const computed = await hashPassword(password, user.salt);
  if (computed !== user.passwordHash) return new Response(JSON.stringify({ error:"invalid_credentials" }), { status:401, headers: JSON_HEADERS });

  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  if (isForm && accept.includes("text/html")) {
    // form POST: redirect to dashboard
    return new Response(null, { status:303, headers: { "Set-Cookie": makeCookieHeader(token, ttl), "Location": "/dashboard" }});
  }
  // API login returns token (json) and cookie
  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: Object.assign({}, JSON_HEADERS, { "Set-Cookie": makeCookieHeader(token, ttl) })});
}

async function handleLogout(req) {
  const cookie = req.headers.get("Cookie") || "";
  const token = getCookieValue(cookie, "session");
  if (token) {
    await kvDelete(`sess:${token}`);
  }
  // clear cookie and redirect to login
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

/* ------------------ main handler ------------------ */
async function handle(req) {
  const url = new URL(req.url);

  // API routes
  if (url.pathname === "/api/register" && req.method === "POST") return handleRegister(req);
  if (url.pathname === "/api/login" && req.method === "POST") return handleLogin(req);
  if (url.pathname === "/api/logout" && (req.method === "POST" || req.method === "GET")) return handleLogout(req);
  if (url.pathname === "/api/me" && req.method === "GET") return handleMe(req);

  // static pages from PAGES_KV
  // map paths: / -> index.html, /login -> login.html, /register -> register.html, /dashboard -> dashboard.html
  const mapping = {
    "/": "index.html",
    "/index.html": "index.html",
    "/login": "login.html",
    "/login.html": "login.html",
    "/register": "register.html",
    "/register.html": "register.html",
    "/dashboard": "dashboard.html",
    "/dashboard.html": "dashboard.html"
  };

  if (mapping[url.pathname]) {
    return await servePageFromPagesKV(mapping[url.pathname], req);
  }

  // fallback: try the path without leading slash as key
  const key = url.pathname.startsWith("/") ? url.pathname.slice(1) : url.pathname;
  if (key) {
    const raw = await PAGES_KV.get(key);
    if (raw) {
      // if someone requests dashboard.html by direct path, also inject check
      if (key === "dashboard.html") return await servePageFromPagesKV("dashboard.html", req);
      return new Response(raw, { status:200, headers:{ "Content-Type": guessContentType(key) }});
    }
  }

  return new Response("Not found", { status:404 });
}
