/**
 * Simple Auth (Register / Login) on Cloudflare Workers using KV.
 *
 * - KV binding: env.MY_KV
 * - Secret: env.SESSION_SECRET (string)
 *
 * Data model (KV):
 * key = "user:email:lowercase"
 * value = JSON.stringify({ email, salt, hash, createdAt, displayName })
 *
 * Session token: base64url(payload) + "." + base64url(HMAC_SHA256(payload, SESSION_SECRET))
 * payload contains: { sub: email, iat, exp }
 */

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (request.method === "GET" && pathname === "/") {
        return htmlResponse(HTML_PAGE);
      }

      if (request.method === "POST" && pathname === "/register") {
        const body = await readBody(request);
        const email = (body.email || "").toLowerCase().trim();
        const password = body.password || "";
        const displayName = body.displayName || "";

        if (!validateEmail(email) || password.length < 6) {
          return jsonResponse({ error: "invalid_input" }, 400);
        }

        const userKey = `user:${email}`;
        const existing = await env.MY_KV.get(userKey);
        if (existing !== null) return jsonResponse({ error: "user_exists" }, 409);

        // create salt + hash
        const salt = randomHex(16);
        const hash = await hashPassword(password, salt);

        const user = {
          email,
          displayName,
          salt,
          hash,
          createdAt: new Date().toISOString()
        };

        await env.MY_KV.put(userKey, JSON.stringify(user));

        // auto-login: issue token
        const token = await createToken({ sub: email }, env.SESSION_SECRET);

        return jsonResponse({ ok: true, token });
      }

      if (request.method === "POST" && pathname === "/login") {
        const body = await readBody(request);
        const email = (body.email || "").toLowerCase().trim();
        const password = body.password || "";

        if (!validateEmail(email) || !password) {
          return jsonResponse({ error: "invalid_input" }, 400);
        }

        const userKey = `user:${email}`;
        const raw = await env.MY_KV.get(userKey);
        if (!raw) return jsonResponse({ error: "invalid_credentials" }, 401);

        const user = JSON.parse(raw);
        const hash = await hashPassword(password, user.salt);
        if (!timingSafeEqual(hash, user.hash)) {
          return jsonResponse({ error: "invalid_credentials" }, 401);
        }

        const token = await createToken({ sub: email }, env.SESSION_SECRET);
        return jsonResponse({ ok: true, token });
      }

      if (request.method === "GET" && pathname === "/me") {
        const token = getBearerToken(request) || getCookieToken(request);
        if (!token) return jsonResponse({ error: "missing_token" }, 401);

        const payload = await verifyToken(token, env.SESSION_SECRET);
        if (!payload) return jsonResponse({ error: "invalid_token" }, 401);

        const userKey = `user:${payload.sub}`;
        const raw = await env.MY_KV.get(userKey);
        if (!raw) return jsonResponse({ error: "not_found" }, 404);

        const user = JSON.parse(raw);
        return jsonResponse({ email: user.email, displayName: user.displayName, createdAt: user.createdAt });
      }

      // unknown route
      return new Response("Not Found", { status: 404 });
    } catch (err) {
      return jsonResponse({ error: "internal_error", message: String(err) }, 500);
    }
  }
};

/* ------------------- Helpers ------------------- */

function htmlResponse(html) {
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

async function readBody(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return request.json();
  }
  if (ct.includes("application/x-www-form-urlencoded")) {
    const form = await request.formData();
    const obj = {};
    for (const [k, v] of form.entries()) obj[k] = v;
    return obj;
  }
  // fallback: try json
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function validateEmail(e) {
  return typeof e === "string" && /\S+@\S+\.\S+/.test(e);
}

function randomHex(bytes = 16) {
  // returns hex string
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  // PBKDF2-SHA256 -> 100000 iterations -> 32 bytes, return hex
  const enc = new TextEncoder();
  const salt = hexToUint8(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  ); // 256 bits => 32 bytes
  return uint8ToHex(new Uint8Array(derivedBits));
}

function hexToUint8(hex) {
  const out = new Uint8Array(hex.length/2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2,i*2+2), 16);
  return out;
}
function uint8ToHex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2,"0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

/* ------------------- Token (HMAC signed) ------------------- */

function base64UrlEncode(u8) {
  // input Uint8Array or string
  let bytes;
  if (typeof u8 === "string") bytes = new TextEncoder().encode(u8);
  else bytes = u8;
  let b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlEncodeStr(str) {
  return base64UrlEncode(new TextEncoder().encode(str));
}
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
  const headerStr = JSON.stringify(header);
  const payloadStr = JSON.stringify(payload);
  const signingInput = base64UrlEncodeStr(headerStr) + "." + base64UrlEncodeStr(payloadStr);

  const sig = await hmacSha256(signingInput, secret);
  return signingInput + "." + sig;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const signingInput = parts[0] + "." + parts[1];
    const sig = parts[2];
    const expected = await hmacSha256(signingInput, secret);
    if (!timingSafeEqual(expected, sig)) return null;
    const payloadStr = new TextDecoder().decode(base64UrlDecodeToUint8(parts[1]));
    const payload = JSON.parse(payloadStr);
    if (payload.exp && Math.floor(Date.now()/1000) > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hmacSha256(message, secret) {
  // secret is string (SESSION_SECRET)
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
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

/* ------------------- Simple HTML UI for testing ------------------- */

const HTML_PAGE = `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Simple Auth (Worker KV)</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial;max-width:760px;margin:28px auto;padding:0 16px}
input,button{padding:8px;margin:6px 0;width:100%}
.box{border:1px solid #ddd;padding:12px;margin-bottom:12px;border-radius:8px}
</style>
</head>
<body>
<h1>Simple Auth (Worker + KV)</h1>

<div class="box">
<h3>Register</h3>
<form id="freg">
  <input name="email" placeholder="Email" required />
  <input name="password" placeholder="Password" type="password" required />
  <input name="displayName" placeholder="Display name (optional)" />
  <button type="submit">Register</button>
</form>
<div id="rmsg"></div>
</div>

<div class="box">
<h3>Login</h3>
<form id="flogin">
  <input name="email" placeholder="Email" required />
  <input name="password" placeholder="Password" type="password" required />
  <button type="submit">Login</button>
</form>
<div id="lmsg"></div>
</div>

<div class="box">
<h3>Check /me</h3>
<button id="bme">Get /me</button>
<pre id="me"></pre>
</div>

<script>
async function postForm(path, fd) {
  const body = {};
  for (const [k, v] of fd.entries()) body[k]=v;
  return fetch(path, { method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify(body) });
}
document.getElementById('freg').onsubmit = async e => {
  e.preventDefault();
  const form = new FormData(e.target);
  const res = await postForm('/register', form);
  const j = await res.json();
  document.getElementById('rmsg').textContent = JSON.stringify(j);
  if (j.token) {
    document.cookie = 'session=' + j.token + '; Secure; SameSite=Lax; path=/';
  }
};
document.getElementById('flogin').onsubmit = async e => {
  e.preventDefault();
  const form = new FormData(e.target);
  const res = await postForm('/login', form);
  const j = await res.json();
  document.getElementById('lmsg').textContent = JSON.stringify(j);
  if (j.token) document.cookie = 'session=' + j.token + '; Secure; SameSite=Lax; path=/';
};
document.getElementById('bme').onclick = async () => {
  const res = await fetch('/me', { credentials: 'include' });
  const j = await res.json();
  document.getElementById('me').textContent = JSON.stringify(j, null, 2);
};
</script>
</body>
</html>`;
