// worker.js
// Bindings expected in wrangler.toml:
//   { binding = "MY_KV", id = "..." }    // for users and sessions
//   { binding = "PAGES_KV", id = "..." } // for static files (index.html, login.html, css, etc.)

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function nowSeconds() { return Math.floor(Date.now() / 1000); }
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// ----- utils -----
function hexToUint8Array(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i*2, 2), 16);
  return arr;
}
function base64urlFromBuffer(buf) {
  // buf: ArrayBuffer or Uint8Array
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randHex(lenBytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(lenBytes));
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

// PBKDF2 hashing (returns base64url)
async function hashPassword(password, saltHex, iterations = 100000) {
  const salt = hexToUint8Array(saltHex);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256
  );
  return base64urlFromBuffer(derived);
}

// ----- KV helpers (MY_KV) -----
// keys:
//   user:<username> -> JSON { username, whatsapp, salt, passwordHash, createdAt }
//   sess:<token>    -> JSON { username, createdAt } stored with expirationTtl
async function kvGet(key) {
  const v = await MY_KV.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvPut(key, obj, opts = {}) {
  if (opts.expirationTtl) {
    await MY_KV.put(key, JSON.stringify(obj), { expirationTtl: opts.expirationTtl });
  } else {
    await MY_KV.put(key, JSON.stringify(obj));
  }
}
async function kvDelete(key) { await MY_KV.delete(key); }

// ----- static assets from PAGES_KV -----
const mimeMap = {
  html: "text/html; charset=utf-8",
  htm: "text/html; charset=utf-8",
  css: "text/css; charset=utf-8",
  js: "application/javascript; charset=utf-8",
  json: "application/json; charset=utf-8",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  svg: "image/svg+xml",
  ico: "image/x-icon",
  txt: "text/plain; charset=utf-8"
};

async function serveStatic(url) {
  let path = url.pathname;
  if (path === "/") path = "/index.html";
  // remove leading slash
  const key = path.startsWith("/") ? path.slice(1) : path;
  if (!key) return null;
  try {
    const data = await PAGES_KV.get(key, { type: "arrayBuffer" });
    if (data === null) return null;
    const ext = key.split(".").pop().toLowerCase();
    const mime = mimeMap[ext] || "application/octet-stream";
    return new Response(data, { headers: { "Content-Type": mime } });
  } catch (e) {
    // if PAGES_KV binding missing, just return null so fallback happens
    return null;
  }
}

// ----- validators -----
function validUsername(u) {
  return typeof u === "string" && /^[a-zA-Z0-9_\-]{3,30}$/.test(u);
}
function validPhone(p) {
  return typeof p === "string" && /^[0-9+\-\s]{7,20}$/.test(p);
}
function validPassword(p) {
  return typeof p === "string" && p.length >= 8;
}

// ----- API handlers -----
async function handleRegister(req) {
  const body = await req.json().catch(() => ({}));
  const username = (body.username || "").trim();
  const whatsapp = (body.whatsapp || "").trim();
  const password = body.password || "";

  if (!validUsername(username)) return jsonResponse({ error: "invalid_username" }, 400);
  if (!validPhone(whatsapp)) return jsonResponse({ error: "invalid_whatsapp" }, 400);
  if (!validPassword(password)) return jsonResponse({ error: "weak_password" }, 400);

  // check exist
  if (await kvGet(`user:${username}`)) return jsonResponse({ error: "user_exists" }, 409);

  const salt = randHex(16);
  const passwordHash = await hashPassword(password, salt);

  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session
  const token = randHex(32);
  const ttl = 60 * 60 * 24 * 7; // 7 days
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;
  return new Response(JSON.stringify({ ok: true, token }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
  });
}

async function handleLogin(req) {
  const body = await req.json().catch(() => ({}));
  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!username || !password) return jsonResponse({ error: "invalid_credentials" }, 400);

  const user = await kvGet(`user:${username}`);
  if (!user) return jsonResponse({ error: "invalid_credentials" }, 401);

  const hashed = await hashPassword(password, user.salt);
  if (hashed !== user.passwordHash) return jsonResponse({ error: "invalid_credentials" }, 401);

  const token = randHex(32);
  const ttl = 60 * 60 * 24 * 7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;
  return new Response(JSON.stringify({ ok: true, token }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
  });
}

async function handleLogout(req) {
  // remove session token from KV if provided in cookie or Authorization
  let token = null;
  const auth = req.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) token = auth.slice(7);
  else {
    const cookie = req.headers.get("Cookie") || "";
    const m = cookie.match(/(?:^|; )session=([^;]+)/);
    if (m) token = m[1];
  }
  if (token) await kvDelete(`sess:${token}`);
  // clear cookie
  const clear = `session=deleted; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`;
  return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json", "Set-Cookie": clear }});
}

async function handleMe(req) {
  let token = null;
  const auth = req.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) token = auth.slice(7);
  else {
    const cookie = req.headers.get("Cookie") || "";
    const m = cookie.match(/(?:^|; )session=([^;]+)/);
    if (m) token = m[1];
  }
  if (!token) return jsonResponse({ error: "no_token" }, 401);
  const sess = await kvGet(`sess:${token}`);
  if (!sess) return jsonResponse({ error: "invalid_token" }, 401);
  const user = await kvGet(`user:${sess.username}`);
  if (!user) return jsonResponse({ error: "not_found" }, 404);
  const { passwordHash, salt, ...safe } = user;
  return jsonResponse(safe, 200);
}

// ----- main fetch -----
addEventListener("fetch", event => {
  event.respondWith(handle(event.request));
});

async function handle(req) {
  const url = new URL(req.url);
  const p = url.pathname;

  // API routes
  if (p === "/api/register" && req.method === "POST") return handleRegister(req);
  if (p === "/api/login" && req.method === "POST") return handleLogin(req);
  if (p === "/api/logout" && (req.method === "POST" || req.method === "GET")) return handleLogout(req);
  if (p === "/api/me" && req.method === "GET") return handleMe(req);

  // static files served from PAGES_KV
  const staticResp = await serveStatic(url);
  if (staticResp) return staticResp;

  // fallback
  return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });
}
