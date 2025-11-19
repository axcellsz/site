/**
 * Worker: serve static pages from Pages_KV and keep Auth API using MY_KV.
 *
 * Bindings expected:
 * - env.MY_KV      (users KV)
 * - env.PAGES_KV   (pages KV, keys: index.html, register.html, css/... etc)
 * - env.SESSION_SECRET (Worker secret)
 *
 * Routes:
 * - POST /register
 * - POST /login
 * - GET  /me
 * - all other paths: serve from PAGES_KV (try exact key, else append .html)
 */

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export default {
  async fetch(request, env) {
    // ensure secret present
    if (!env.SESSION_SECRET || String(env.SESSION_SECRET).length === 0) {
      return new Response(JSON.stringify({
        error: "missing_session_secret",
        message: "SESSION_SECRET not set in Worker secrets."
      }, null, 2), { status: 500, headers: { "Content-Type": "application/json" }});
    }

    const url = new URL(request.url);
    let path = url.pathname.replace(/\/+$/, "") || "/";

    // API / auth routes
    if (request.method === "POST" && path === "/register") {
      return handleRegister(request, env);
    }
    if (request.method === "POST" && path === "/login") {
      return handleLogin(request, env);
    }
    if (request.method === "GET" && path === "/me") {
      return handleMe(request, env);
    }

    // Serve static from PAGES_KV
    return serveFromPagesKV(request, env);
  }
};

/* ---------------- Static serving ---------------- */

async function serveFromPagesKV(request, env) {
  const url = new URL(request.url);
  let key = url.pathname.replace(/^\//, "");
  if (!key || key === "") key = "index.html";

  // Try exact key first (for css/js/images)
  let value = await env.PAGES_KV.get(key);
  if (value === null && !key.includes('.')) {
    // try key + .html
    key = key + ".html";
    value = await env.PAGES_KV.get(key);
  }

  if (value === null) {
    return new Response("Not Found", { status: 404 });
  }

  const ext = key.split('.').pop().toLowerCase();
  const ct = ext === 'html' ? 'text/html; charset=utf-8'
           : ext === 'css'  ? 'text/css'
           : ext === 'js'   ? 'application/javascript'
           : ext === 'json' ? 'application/json'
           : ext === 'svg'  ? 'image/svg+xml'
           : ext === 'png'  ? 'image/png'
           : ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg'
           : 'application/octet-stream';

  return new Response(value, {
    headers: {
      "Content-Type": ct,
      "Cache-Control": "public, max-age=3600"
    }
  });
}

/* ---------------- Auth handlers (register, login, me) ---------------- */

async function handleRegister(request, env) {
  try {
    const body = await readBody(request);
    const email = (body.email || "").toLowerCase().trim();
    const password = body.password || "";
    const displayName = (body.displayName || "").trim();
    const phone = (body.phone || "").trim();

    if (!validateEmail(email) || password.length < 8 || !displayName) {
      return jsonResponse({ error: "invalid_input" }, 400);
    }
    if (!/^\+?[0-9]{8,15}$/.test(phone.replace(/\s+/g,''))) {
      return jsonResponse({ error: "invalid_phone" }, 400);
    }

    const userKey = `user:${email}`;
    const existing = await env.MY_KV.get(userKey);
    if (existing !== null) return jsonResponse({ error: "user_exists" }, 409);

    const salt = randomHex(16);
    const hash = await hashPassword(password, salt);

    const user = { email, displayName, phone, salt, hash, createdAt: new Date().toISOString(), role: "user" };
    await env.MY_KV.put(userKey, JSON.stringify(user));

    const token = await createToken({ sub: email }, env.SESSION_SECRET);
    return jsonResponse({ ok: true, token });
  } catch (err) {
    return jsonResponse({ error: "internal_error", message: String(err) }, 500);
  }
}

async function handleLogin(request, env) {
  try {
    const body = await readBody(request);
    const email = (body.email || "").toLowerCase().trim();
    const password = body.password || "";

    if (!validateEmail(email) || !password) return jsonResponse({ error: "invalid_input" }, 400);

    const userKey = `user:${email}`;
    const raw = await env.MY_KV.get(userKey);
    if (!raw) return jsonResponse({ error: "invalid_credentials" }, 401);

    const user = JSON.parse(raw);
    const hash = await hashPassword(password, user.salt);
    if (!timingSafeEqual(hash, user.hash)) return jsonResponse({ error: "invalid_credentials" }, 401);

    const token = await createToken({ sub: email }, env.SESSION_SECRET);
    return jsonResponse({ ok: true, token });
  } catch (err) {
    return jsonResponse({ error: "internal_error", message: String(err) }, 500);
  }
}

async function handleMe(request, env) {
  try {
    const token = getBearerToken(request) || getCookieToken(request);
    if (!token) return jsonResponse({ error: "missing_token" }, 401);

    const payload = await verifyToken(token, env.SESSION_SECRET);
    if (!payload) return jsonResponse({ error: "invalid_token" }, 401);

    const userKey = `user:${payload.sub}`;
    const raw = await env.MY_KV.get(userKey);
    if (!raw) return jsonResponse({ error: "not_found" }, 404);

    const user = JSON.parse(raw);
    return jsonResponse({ email: user.email, displayName: user.displayName, phone: user.phone, createdAt: user.createdAt });
  } catch (err) {
    return jsonResponse({ error: "internal_error", message: String(err) }, 500);
  }
}

/* ---------------- Helpers (body, responses, hashing, tokens) ---------------- */

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

async function readBody(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/json")) return request.json();
  if (ct.includes("application/x-www-form-urlencoded")) {
    const form = await request.formData();
    const obj = {};
    for (const [k, v] of form.entries()) obj[k] = v;
    return obj;
  }
  try { return await request.json(); } catch { return {}; }
}

function validateEmail(e) { return typeof e === "string" && /\S+@\S+\.\S+/.test(e); }

function randomHex(bytes = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = hexToUint8(saltHex);
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derivedBits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return uint8ToHex(new Uint8Array(derivedBits));
}
function hexToUint8(hex) {
  const out = new Uint8Array(hex.length/2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2,i*2+2), 16);
  return out;
}
function uint8ToHex(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2,"0")).join(""); }
function timingSafeEqual(a,b) { if (a.length !== b.length) return false; let r=0; for (let i=0;i<a.length;i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r===0; }

/* ---------------- Token (HMAC-SHA256 signed compact token) ---------------- */

function base64UrlEncode(u8) {
  let bytes; if (typeof u8 === "string") bytes = new TextEncoder().encode(u8); else bytes = u8;
  let b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlEncodeStr(str) { return base64UrlEncode(new TextEncoder().encode(str)); }
function base64UrlDecodeToUint8(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

async function createToken(payloadObj, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now()/1000);
  const payload = Object.assign({ iat: now, exp: now + TOKEN_TTL_SECONDS }, payloadObj);
  const signingInput = base64UrlEncodeStr(JSON.stringify(header)) + "." + base64UrlEncodeStr(JSON.stringify(payload));
  const sig = await hmacSha256(signingInput, secret);
  return signingInput + "." + sig;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const signingInput = parts[0] + "." + parts[1];
    const expected = await hmacSha256(signingInput, secret);
    if (!timingSafeEqual(expected, parts[2])) return null;
    const payloadStr = new TextDecoder().decode(base64UrlDecodeToUint8(parts[1]));
    const payload = JSON.parse(payloadStr);
    if (payload.exp && Math.floor(Date.now()/1000) > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function hmacSha256(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return base64UrlEncode(new Uint8Array(sig));
}

function getBearerToken(request) {
  const h = request.headers.get("authorization") || "";
  if (h.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
  return null;
}
function getCookieToken(request) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}
