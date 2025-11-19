// worker.js — sessions in KV (no SESSION_SECRET required)
// Uses single KV binding: MY_KV
// Keys:
//   user:<username>  -> JSON { username, whatsapp, salt, passwordHash, createdAt }
//   sess:<token>     -> JSON { username, createdAt } (stored with expirationTtl)

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function nowSeconds(){ return Math.floor(Date.now()/1000); }
function randHex(len=48){
  const b = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
}
function jsonResponse(obj, status=200){ return new Response(JSON.stringify(obj), { status, headers: { "Content-Type":"application/json" } }); }

async function hashPassword(password, saltHex, iterations = 100000) {
  const pwKey = await crypto.subtle.importKey("raw", encoder.encode(password), {name:"PBKDF2"}, false, ["deriveBits"]);
  const salt = hexToUint8Array(saltHex);
  const derived = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, pwKey, 256);
  return base64url(new Uint8Array(derived));
}
function hexToUint8Array(hex){
  const arr = new Uint8Array(hex.length/2);
  for(let i=0;i<arr.length;i++) arr[i]=parseInt(hex.substr(i*2,2),16);
  return arr;
}
function base64url(u8){
  let s = btoa(String.fromCharCode(...u8));
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

addEventListener("fetch", e => e.respondWith(handle(e.request)));

async function handle(req){
  const url = new URL(req.url);
  const p = url.pathname;
  try {
    if (p === "/api/register" && req.method === "POST") return await handleRegister(req);
    if (p === "/api/login" && req.method === "POST") return await handleLogin(req);
    if (p === "/api/me" && req.method === "GET") return await handleMe(req);
    return new Response("Not found", { status: 404 });
  } catch(err){
    return jsonResponse({ error: "internal_error", message: String(err) }, 500);
  }
}

// ---------- helpers to use MY_KV ----------
async function kvGet(key){ const v = await MY_KV.get(key); return v ? JSON.parse(v) : null; }
async function kvPut(key, obj, opts = {}) {
  // opts can include expirationTtl (seconds)
  if (opts.expirationTtl) {
    // Workers KV API via put accepts a third arg object with { expirationTtl } in runtime
    await MY_KV.put(key, JSON.stringify(obj), { expirationTtl: opts.expirationTtl });
  } else {
    await MY_KV.put(key, JSON.stringify(obj));
  }
}
async function kvDelete(key){ await MY_KV.delete(key); }

// ---------- endpoints ----------
async function handleRegister(req){
  const body = await req.json().catch(()=>({}));
  const username = (body.username||"").trim();
  const whatsapp = (body.whatsapp||"").trim();
  const password = body.password || "";

  if (!/^[a-zA-Z0-9_\-]{3,30}$/.test(username)) return jsonResponse({ error: "invalid_username" }, 400);
  if (!/^[0-9+\-\s]{7,20}$/.test(whatsapp)) return jsonResponse({ error: "invalid_whatsapp" }, 400);
  if (typeof password !== "string" || password.length < 8) return jsonResponse({ error: "weak_password" }, 400);

  // check exist
  if (await kvGet(`user:${username}`)) return jsonResponse({ error: "user_exists" }, 409);

  const salt = randHex(16);
  const passwordHash = await hashPassword(password, salt);

  const user = { username, whatsapp, salt, passwordHash, createdAt: new Date().toISOString() };
  await kvPut(`user:${username}`, user);

  // create session token immediately
  const token = randHex(32);
  const ttl = 60*60*24*7; // 7 days
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  // set cookie
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;
  return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: { "Content-Type":"application/json", "Set-Cookie": cookie }});
}

async function handleLogin(req){
  const body = await req.json().catch(()=>({}));
  const username = (body.username||"").trim();
  const password = body.password || "";

  if (!username || !password) return jsonResponse({ error: "invalid_credentials" }, 400);

  const user = await kvGet(`user:${username}`);
  if (!user) return jsonResponse({ error: "invalid_credentials" }, 401);

  const hashed = await hashPassword(password, user.salt);
  if (hashed !== user.passwordHash) return jsonResponse({ error: "invalid_credentials" }, 401);

  const token = randHex(32);
  const ttl = 60*60*24*7; // 7 days
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });

  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;
  return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: { "Content-Type":"application/json", "Set-Cookie": cookie }});
}

async function handleMe(req){
  // get token from cookie or Authorization Bearer
  let token = null;
  const auth = req.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) token = auth.slice(7);
  else {
    const cookie = req.headers.get("Cookie") || "";
    const m = cookie.match(/(?:^|; )session=([^;]+)/);
    if (m) token = m[1];
  }
  if (!token) return jsonResponse({ error: "no_token" }, 401);

  const s = await kvGet(`sess:${token}`);
  if (!s) return jsonResponse({ error: "invalid_token" }, 401);

  const user = await kvGet(`user:${s.username}`);
  if (!user) return jsonResponse({ error: "not_found" }, 404);

  // don't return password/salt
  const { passwordHash, salt, ...safe } = user;
  return jsonResponse(safe);
}
