// worker.js - simple auth + pages from KV
// Bindings required: MY_KV (users & sessions), PAGES_KV (static files)

addEventListener("fetch", event => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  try {
    const url = new URL(req.url);
    // API routes
    if (url.pathname.startsWith("/api/")) {
      if (req.method === "POST" && url.pathname === "/api/register") return handleRegister(req);
      if (req.method === "POST" && url.pathname === "/api/login") return handleLogin(req);
      if (req.method === "GET" && url.pathname === "/api/me") return handleMe(req);
      return jsonResponse({ error: "not_found" }, 404);
    }

    // Serve static pages from PAGES_KV
    if (req.method === "GET") return serveFromKV(req);

    return jsonResponse({ error: "method_not_allowed" }, 405);
  } catch (e) {
    return jsonResponse({ error: "internal", message: String(e) }, 500);
  }
}

/* ================= helpers ================= */

function jsonResponse(obj, status = 200, headers = {}) {
  const h = Object.assign({ "Content-Type": "application/json; charset=utf-8" }, headers);
  return new Response(JSON.stringify(obj), { status, headers: h });
}

async function parseBodyFlexible(req) {
  const ct = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct === "application/json") {
    return await req.json().catch(()=>({}));
  }
  if (ct === "application/x-www-form-urlencoded") {
    const t = await req.text();
    return Object.fromEntries(new URLSearchParams(t));
  }
  // fallback try json then text
  try { return await req.json(); } catch(e) { 
    const t = await req.text(); 
    return t ? { raw: t } : {};
  }
}

/* ================ KV serving ================ */

async function serveFromKV(req) {
  const url = new URL(req.url);
  let path = url.pathname;

  if (path === "/") path = "/index.html";

  // If no extension, add .html
  if (!path.includes(".")) path = path.replace(/\/+$/, "") + ".html";

  const key = path.replace(/^\/+/, "");
  const content = await PAGES_KV.get(key, { type: "text" });
  if (content === null) return new Response("Not found", { status: 404, headers: { "Content-Type":"text/plain" } });

  const ext = key.split(".").pop().toLowerCase();
  const types = {
    html: "text/html; charset=utf-8",
    css: "text/css; charset=utf-8",
    js: "application/javascript; charset=utf-8",
    json: "application/json; charset=utf-8",
    svg: "image/svg+xml",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    ico: "image/x-icon"
  };

  return new Response(content, { status: 200, headers: { "Content-Type": types[ext] || "application/octet-stream" }});
}

/* ================ Simple auth (MY_KV) ================ */
/* stored keys:
   user:{username} -> JSON { username, whatsapp, salt, passwordHash, createdAt }
   sess:{token}   -> JSON { username, createdAt }
*/

function randHex(len = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes).map(b => b.toString(16).padStart(2,"0")).join("");
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
}

function validUsername(s){ return typeof s==="string" && /^[a-zA-Z0-9_.-]{3,32}$/.test(s); }
function validPhone(s){ return typeof s==="string" && s.replace(/\s|\-/g,"").length >= 6; }
function validPassword(s){ return typeof s==="string" && s.length >= 6; }

async function kvGet(key) {
  const v = await MY_KV.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvPut(key, obj, opts={}) {
  const value = JSON.stringify(obj);
  if (opts.expirationTtl) {
    await MY_KV.put(key, value, { expirationTtl: opts.expirationTtl });
  } else {
    await MY_KV.put(key, value);
  }
}

/* -------- register -------- */
async function handleRegister(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim();
  const whatsapp = (body.whatsapp || body.wa || "").trim();
  const password = body.password || "";

  if (!validUsername(username)) return jsonResponse({ error: "invalid_username" }, 400);
  if (!validPhone(whatsapp)) return jsonResponse({ error: "invalid_whatsapp" }, 400);
  if (!validPassword(password)) return jsonResponse({ error: "weak_password" }, 400);

  if (await kvGet(`user:${username}`)) return jsonResponse({ error: "user_exists" }, 409);

  const salt = randHex(12);
  const passwordHash = await sha256Hex(password + salt);
  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session token optional
  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // if HTML form wants redirect, redirect to login page
  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  if (isForm && accept.includes("text/html")) {
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/login" }});
  }

  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: { "Content-Type":"application/json", "Set-Cookie": cookie }});
}

/* -------- login -------- */
async function handleLogin(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!validUsername(username)) return jsonResponse({ error: "invalid_credentials" }, 400);
  const user = await kvGet(`user:${username}`);
  if (!user) return jsonResponse({ error: "invalid_credentials" }, 401);

  const hash = await sha256Hex(password + user.salt);
  if (hash !== user.passwordHash) return jsonResponse({ error: "invalid_credentials" }, 401);

  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // if HTML form, redirect to dashboard
  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  if (isForm && accept.includes("text/html")) {
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/dashboard" }});
  }

  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: { "Content-Type":"application/json", "Set-Cookie": cookie }});
}

/* -------- /api/me -------- */
async function handleMe(req) {
  const cookie = parseCookies(req.headers.get("Cookie") || "");
  const token = cookie.session;
  if (!token) return jsonResponse({ error: "unauthenticated" }, 401);
  const sess = await kvGet(`sess:${token}`);
  if (!sess) return jsonResponse({ error: "unauthenticated" }, 401);
  const user = await kvGet(`user:${sess.username}`);
  if (!user) return jsonResponse({ error: "unauthenticated" }, 401);
  return jsonResponse({ ok:true, username: user.username, whatsapp: user.whatsapp, createdAt: user.createdAt });
}

function parseCookies(cookieStr) {
  return Object.fromEntries((cookieStr||"").split(";").map(s=>s.trim()).filter(Boolean).map(p=> {
    const idx = p.indexOf("=");
    return [ idx===-1 ? p : p.slice(0,idx), idx===-1 ? "" : decodeURIComponent(p.slice(idx+1)) ];
  }));
}
