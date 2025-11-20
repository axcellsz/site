// worker.js (paste & deploy)
// Bindings expected in wrangler.toml: MY_KV (users & sessions), PAGES_KV (static pages)

addEventListener("fetch", event => {
  event.respondWith(handleEvent(event));
});

async function handleEvent(event) {
  const req = event.request;
  const url = new URL(req.url);
  try {
    // Routes:
    if (url.pathname === "/api/login" && req.method === "POST") return await handleLogin(req);
    if (url.pathname === "/api/register" && req.method === "POST") return await handleRegister(req);
    // serve pages from Pages KV if exists: / -> index.html, /login -> login.html, /register -> register.html, /dashboard -> dashboard.html
    return await handlePages(req, url.pathname);
  } catch (err) {
    return new Response(JSON.stringify({ error: "internal_error", message: String(err) }), { status: 500, headers: { "Content-Type": "application/json" }});
  }
}

// ---------------- helpers ----------------
async function kvGet(key) {
  const v = await MY_KV.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvPut(key, obj, opts) {
  const val = JSON.stringify(obj);
  if (opts && opts.expirationTtl) {
    await MY_KV.put(key, val, { expirationTtl: opts.expirationTtl });
  } else {
    await MY_KV.put(key, val);
  }
}
function randHex(bytes=16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Array.from(a).map(b => b.toString(16).padStart(2,"0")).join("");
}
async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const h = Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join("");
  return h;
}

// parse body for JSON or form
async function parseBodyFlexible(req) {
  const ct = (req.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct === "application/json") {
    return await req.json().catch(()=>({}));
  }
  // form submissions (application/x-www-form-urlencoded or multipart/form-data)
  if (ct === "application/x-www-form-urlencoded" || ct === "multipart/form-data") {
    const fd = await req.formData();
    const out = {};
    for (const [k,v] of fd) out[k] = v;
    return out;
  }
  // fallback: try text -> parse json or urlencoded
  const t = await req.text().catch(()=>"");
  try { return JSON.parse(t); } catch(e){}
  // parse urlencoded fallback
  const params = new URLSearchParams(t);
  const obj = {};
  for (const [k,v] of params) obj[k]=v;
  return obj;
}

function jsonResponse(obj, status=200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type":"application/json" }});
}

// ---------------- auth helpers ----------------
async function hashPassword(password, salt) {
  // simple: sha256(salt + password)
  return await sha256Hex(salt + password);
}
function validUsername(u){ return typeof u === "string" && /^[a-zA-Z0-9_.-]{3,40}$/.test(u); }
function validPhone(p){ return typeof p === "string" && p.trim().length >= 6; }
function validPassword(p){ return typeof p === "string" && p.length >= 6; }

// ---------------- API: register ----------------
async function handleRegister(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username||"").trim();
  const whatsapp = (body.whatsapp||"").trim();
  const password = body.password || "";

  if (!validUsername(username)) return jsonResponse({ error: "invalid_username" }, 400);
  if (!validPhone(whatsapp)) return jsonResponse({ error: "invalid_whatsapp" }, 400);
  if (!validPassword(password)) return jsonResponse({ error: "weak_password" }, 400);

  if (await kvGet(`user:${username}`)) return jsonResponse({ error: "user_exists" }, 409);

  const salt = randHex(12);
  const passwordHash = await hashPassword(password, salt);
  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session token (optional) and store
  const token = randHex(32);
  const ttl = 60*60*24*7; // 7 days
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // determine whether to redirect (browser form) or return json (API)
  const accept = (req.headers.get("Accept")||"");
  const ctype = (req.headers.get("Content-Type")||"").split(";")[0].trim();
  const isForm = ctype === "application/x-www-form-urlencoded" || ctype === "multipart/form-data";
  const wantsHtml = accept.includes("text/html") || !!req.headers.get("Referer");

  if (isForm || wantsHtml) {
    // redirect to login page with a query flag
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/login?registered=1" }});
  }
  return jsonResponse({ ok: true, token }, 200);
}

// ---------------- API: login ----------------
async function handleLogin(req) {
  const body = await parseBodyFlexible(req);
  const username = (body.username||"").trim();
  const password = body.password || "";

  if (!validUsername(username) || !validPassword(password)) {
    return maybeHtmlFailure(req, { error: "invalid_credentials" }, 401);
  }

  const user = await kvGet(`user:${username}`);
  if (!user) return maybeHtmlFailure(req, { error: "invalid_credentials" }, 401);

  const candidate = await hashPassword(password, user.salt);
  if (candidate !== user.passwordHash) return maybeHtmlFailure(req, { error: "invalid_credentials" }, 401);

  // ok -> create session
  const token = randHex(32);
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // If browser form -> redirect to dashboard
  const accept = (req.headers.get("Accept")||"");
  const ctype = (req.headers.get("Content-Type")||"").split(";")[0].trim();
  const isForm = ctype === "application/x-www-form-urlencoded" || ctype === "multipart/form-data";
  const wantsHtml = accept.includes("text/html") || !!req.headers.get("Referer");

  if (isForm || wantsHtml) {
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/dashboard" }});
  }

  // API JSON response
  return jsonResponse({ ok: true, token }, 200).then(r => {
    // attach cookie header isn't possible directly with jsonResponse helper, so rebuild
    return new Response(JSON.stringify({ ok:true, token }), { status:200, headers:{ "Content-Type":"application/json", "Set-Cookie": cookie }});
  });
}

function maybeHtmlFailure(req, obj, status=400) {
  const accept = (req.headers.get("Accept")||"");
  const ctype = (req.headers.get("Content-Type")||"").split(";")[0].trim();
  const isForm = ctype === "application/x-www-form-urlencoded" || ctype === "multipart/form-data";
  const wantsHtml = accept.includes("text/html") || !!req.headers.get("Referer");
  if (isForm || wantsHtml) {
    // redirect back to login with error query
    return new Response(null, { status: 303, headers: { "Location": "/login?error=1" }});
  }
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type":"application/json" }});
}

// ---------------- static pages from Pages KV ----------------
async function handlePages(req, pathname) {
  // normalize
  if (pathname === "/") pathname = "/index.html";
  // map common routes
  if (pathname === "/login") pathname = "/login.html";
  if (pathname === "/register") pathname = "/register.html";
  if (pathname === "/dashboard") pathname = "/dashboard.html";

  // remove leading slash to use as key in PAGES_KV
  const key = pathname.startsWith("/") ? pathname.slice(1) : pathname;
  const s = await PAGES_KV.get(key);
  if (s) {
    // return raw html
    // basic content-type based on extension
    const ct = key.endsWith(".html") ? "text/html; charset=utf-8" :
               key.endsWith(".css") ? "text/css; charset=utf-8" :
               key.endsWith(".js") ? "application/javascript; charset=utf-8" :
               "text/plain; charset=utf-8";
    return new Response(s, { status:200, headers: { "Content-Type": ct }});
  }
  return new Response("Not found", { status: 404, headers: { "Content-Type":"text/plain" }});
}
