// worker.js - Simple Worker + KV auth (username + whatsapp + password)
// Requires KV bindings: MY_KV (users + sessions) and PAGES_KV (static pages)
// Endpoints:
//  GET  /            -> serve index.html from PAGES_KV (or 404)
//  GET  /register    -> serve register.html
//  GET  /login       -> serve login.html
//  POST /api/register
//  POST /api/login

addEventListener("fetch", event => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  try {
    const url = new URL(req.url);
    const path = url.pathname;

    // Static pages (serve from PAGES_KV)
    if (req.method === "GET" && (path === "/" || path === "/index.html")) {
      return await serveFromPagesKV("index.html");
    }
    if (req.method === "GET" && path === "/register") return await serveFromPagesKV("register.html");
    if (req.method === "GET" && path === "/login") return await serveFromPagesKV("login.html");

    // API routes
    if (path === "/api/register" && req.method === "POST") return await handleRegister(req);
    if (path === "/api/login" && req.method === "POST") return await handleLogin(req);

    // fallback: try to serve same path from PAGES_KV (e.g., /styles.css)
    if (req.method === "GET") {
      const key = path.replace(/^\/+/, "") || "index.html";
      return await serveFromPagesKV(key);
    }

    return jsonResponse({ error: "not_found" }, 404);
  } catch (err) {
    console.error("Unhandled error:", err);
    return jsonResponse({ error: "internal_error", message: String(err) }, 500);
  }
}

/* ----------------- helpers: serving static from PAGES_KV ----------------- */
async function serveFromPagesKV(key) {
  // PAGES_KV binding must exist
  if (typeof PAGES_KV === "undefined") {
    return jsonResponse({ error: "pages_kv_not_bound" }, 500);
  }
  const value = await PAGES_KV.get(key);
  if (value === null) {
    return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });
  }
  // try detect content-type by extension (basic)
  const ct = contentTypeForKey(key);
  return new Response(value, { status: 200, headers: { "Content-Type": ct } });
}
function contentTypeForKey(key) {
  if (key.endsWith(".html")) return "text/html; charset=utf-8";
  if (key.endsWith(".css")) return "text/css; charset=utf-8";
  if (key.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (key.endsWith(".json")) return "application/json; charset=utf-8";
  if (key.endsWith(".png")) return "image/png";
  if (key.endsWith(".jpg") || key.endsWith(".jpeg")) return "image/jpeg";
  return "text/plain; charset=utf-8";
}

/* ----------------- API: register (supports JSON and form) ----------------- */
async function handleRegister(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim();
  const whatsapp = (body.whatsapp || body.wa || "").trim();
  const password = body.password || "";

  if (!validUsername(username)) return jsonResponse({ error: "invalid_username" }, 400);
  if (!validPhone(whatsapp)) return jsonResponse({ error: "invalid_whatsapp" }, 400);
  if (!validPassword(password)) return jsonResponse({ error: "weak_password" }, 400);

  if (await kvGet(`user:${username}`)) return jsonResponse({ error: "user_exists" }, 409);

  const salt = randHex(16);
  const passwordHash = await hashPassword(password, salt);
  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session token immediately (optional) — still create but we redirect to login page
  const token = randHex(32);
  const ttl = 60 * 60 * 24 * 7; // 7 days
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // If form submission and wants HTML, redirect to login page (with flag)
  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  const wantsHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");
  if (isForm && wantsHtml) {
    // redirect to login page and inform success via query string
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/login?registered=1" }});
  }

  // API JSON response
  return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": cookie }});
}

/* ----------------- API: login ----------------- */
async function handleLogin(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!username || !password) return jsonResponse({ error: "invalid_credentials" }, 400);

  const user = await kvGet(`user:${username}`);
  if (!user) return jsonResponse({ error: "invalid_credentials" }, 401);

  const passwordHash = await hashPassword(password, user.salt);
  if (passwordHash !== user.passwordHash) return jsonResponse({ error: "invalid_credentials" }, 401);

  // success -> create session
  const token = randHex(32);
  const ttl = 60 * 60 * 24 * 7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // if coming from form, redirect to /dashboard (or /)
  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  const wantsHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");
  if (isForm && wantsHtml) {
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/dashboard" }});
  }

  return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": cookie }});
}

/* ----------------- KV helpers ----------------- */
async function kvGet(key) {
  if (typeof MY_KV === "undefined") throw new Error("MY_KV not bound");
  const v = await MY_KV.get(key);
  if (v === null) return null;
  try { return JSON.parse(v); } catch (e) { return v; }
}
async function kvPut(key, value, opts = {}) {
  if (typeof MY_KV === "undefined") throw new Error("MY_KV not bound");
  const str = typeof value === "string" ? value : JSON.stringify(value);
  if (opts && (opts.expirationTtl || opts.expiration)) {
    // Cloudflare KV options: expiration or expirationTtl
    const putOpts = {};
    if (opts.expirationTtl) putOpts.expirationTtl = opts.expirationTtl;
    if (opts.expiration) putOpts.expiration = opts.expiration;
    return await MY_KV.put(key, str, putOpts);
  }
  return await MY_KV.put(key, str);
}

/* ----------------- util: parse body JSON or form ----------------- */
async function parseBodyFlexible(req) {
  const ctype = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  if (!ctype) return {};
  if (ctype === "application/json") {
    try { return await req.json(); } catch (e) { return {}; }
  }
  if (ctype === "application/x-www-form-urlencoded") {
    const text = await req.text();
    const params = new URLSearchParams(text);
    const obj = {};
    for (const [k, v] of params) obj[k] = v;
    return obj;
  }
  // fallback to text parse attempt
  try {
    const t = await req.text();
    try { return JSON.parse(t); } catch (e) { return {}; }
  } catch (e) {
    return {};
  }
}

/* ----------------- simple validators ----------------- */
function validUsername(s) {
  return typeof s === "string" && s.length >= 3 && /^[a-zA-Z0-9._-]+$/.test(s);
}
function validPhone(s) {
  // basic phone check: digits, +, spaces, 7-16 chars
  return typeof s === "string" && /^[0-9+ ]{7,20}$/.test(s);
}
function validPassword(s) {
  return typeof s === "string" && s.length >= 6;
}

/* ----------------- hashing & random ----------------- */
function randHex(len) {
  // len = number of bytes -> hex length = len*2
  const arr = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hashPassword(password, salt) {
  // simple SHA-256 of salt + password, returned as hex
  const enc = new TextEncoder();
  const data = enc.encode(salt + password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(hash));
}
function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* ----------------- small response helper ----------------- */
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" }});
}
