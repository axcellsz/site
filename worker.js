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
<html lang="id">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Daftar — My Site</title>
<style>
  :root{
    --bg:#f7fafc;
    --card:#ffffff;
    --muted:#6b7280;
    --accent:#2563eb;
    --danger:#dc2626;
    --success:#16a34a;
    --radius:12px;
    --shadow:0 6px 18px rgba(16,24,40,0.08);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
  }
  body{
    margin:0;
    background:linear-gradient(180deg,#eef2ff 0%, var(--bg) 100%);
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:28px;
  }
  .card{
    width:100%;
    max-width:760px;
    background:var(--card);
    border-radius:var(--radius);
    box-shadow:var(--shadow);
    padding:28px;
    box-sizing:border-box;
  }
  h1{margin:0 0 8px;font-size:20px}
  p.lead{margin:0 0 18px;color:var(--muted)}
  .grid{display:grid;grid-template-columns:1fr 320px;gap:20px}
  @media (max-width:820px){ .grid{grid-template-columns:1fr} }

  form{display:flex;flex-direction:column;gap:12px}
  label{font-size:13px;color:#111827}
  input[type="text"], input[type="email"], input[type="password"]{
    padding:11px 12px;border:1px solid #e6e9ef;border-radius:8px;font-size:14px;
    outline:none;transition:box-shadow .12s, border-color .12s;
  }
  input:focus{box-shadow:0 0 0 4px rgba(37,99,235,0.06);border-color:var(--accent)}
  .btn{
    background:var(--accent);color:#fff;padding:11px;border-radius:10px;border:0;font-weight:600;
    cursor:pointer;font-size:15px;
  }
  .btn:disabled{opacity:.6;cursor:not-allowed}
  .muted{color:var(--muted);font-size:13px}
  .note{font-size:13px;color:var(--muted);margin-top:8px}

  .strength{
    height:9px;border-radius:999px;background:#f1f5f9;overflow:hidden;margin-top:6px;
  }
  .strength > i{display:block;height:100%;}
  .s-weak{width:33%;background:#f97316}
  .s-medium{width:66%;background:#f59e0b}
  .s-strong{width:100%;background:#16a34a}

  .msg{padding:10px;border-radius:8px;font-size:14px}
  .msg.error{background:#fff5f5;border:1px solid #fecaca;color:var(--danger)}
  .msg.success{background:#f0fdf4;border:1px solid #bbf7d0;color:var(--success)}
  .small{font-size:13px;color:var(--muted)}

  .right{
    background:linear-gradient(180deg, #fbfbff 0%, #ffffff 100%);
    border-radius:10px;padding:16px;border:1px solid #eef2ff;
    display:flex;flex-direction:column;gap:12px;align-items:flex-start;
  }
  .logo{height:46px;width:46px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#06b6d4);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700}
</style>
</head>
<body>
  <main class="card" role="main" aria-labelledby="title">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:8px">
      <div>
        <h1 id="title">Buat Akun Baru</h1>
        <p class="lead">Daftar cepat dan aman. Gunakan email aktif — konfirmasi tidak wajib untuk demo.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <div class="logo">S</div>
      </div>
    </div>

    <div class="grid">
      <section>
        <form id="registerForm" novalidate>
          <div>
            <label for="email">Alamat Email</label>
            <input id="email" name="email" type="email" inputmode="email" autocomplete="email" placeholder="nama@domain.com" required />
          </div>

          <div>
            <label for="displayName">Nama Tampilan</label>
            <input id="displayName" name="displayName" type="text" autocomplete="name" placeholder="Contoh: Andi" />
          </div>

          <div>
            <label for="password">Kata Sandi <span class="small"> (min 8 karakter)</span></label>
            <input id="password" name="password" type="password" autocomplete="new-password" placeholder="Tulis kata sandi" required />
            <div class="strength" aria-hidden="true" style="margin-top:8px"><i id="strengthBar" class="s-weak" style="width:0"></i></div>
            <div id="pwdText" class="small" style="margin-top:6px">Kekuatan kata sandi: <strong id="pwdLabel">—</strong></div>
          </div>

          <div>
            <label for="password2">Konfirmasi Kata Sandi</label>
            <input id="password2" name="password2" type="password" autocomplete="new-password" placeholder="Ulangi kata sandi" required />
          </div>

          <div id="formMsg" aria-live="polite"></div>

          <div style="display:flex;gap:12px;align-items:center;margin-top:6px">
            <button id="submitBtn" class="btn" type="submit">Buat Akun</button>
            <div class="muted small">Sudah punya akun? <a href="/" style="color:var(--accent);text-decoration:none">Login</a></div>
          </div>

          <p class="note">Dengan mendaftar, kamu setuju dengan <strong>Terms</strong> kami. Ini demo — jangan pakai password penting.</p>
        </form>
      </section>

      <aside class="right" aria-hidden="false">
        <strong>Tips keamanan</strong>
        <ul style="margin:0;padding-left:18px;color:var(--muted);font-size:14px;line-height:1.6">
          <li>Gunakan kata sandi unik minimal 8 karakter.</li>
          <li>Gabungkan huruf besar, kecil, angka, simbol untuk kekuatan lebih tinggi.</li>
          <li>Simpan kata sandi penting di password manager.</li>
        </ul>

        <div style="width:100%;margin-top:10px">
          <div class="small">Contoh:</div>
          <div class="muted small" style="margin-top:6px">contoh@domain.com — KataSandi!2025</div>
        </div>
      </aside>
    </div>
  </main>

<script>
(async function(){

  function el(id){ return document.getElementById(id); }
  const form = el('registerForm');
  const email = el('email');
  const displayName = el('displayName');
  const password = el('password');
  const password2 = el('password2');
  const submitBtn = el('submitBtn');
  const formMsg = el('formMsg');
  const strengthBar = el('strengthBar');
  const pwdLabel = el('pwdLabel');

  function showMsg(type, text){
    formMsg.innerHTML = '<div class="msg '+(type==='error'?'error':'success')+'">'+text+'</div>';
  }
  function clearMsg(){ formMsg.innerHTML = ''; }

  function validateEmail(v){
    return /\S+@\S+\.\S+/.test(v);
  }

  function passwordStrength(p){
    // simple scoring: length + variety
    let score = 0;
    if (p.length >= 8) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    return score; // 0..4
  }

  function updateStrengthUI(p){
    const s = passwordStrength(p);
    if (!p) { strengthBar.style.width='0%'; strengthBar.className=''; pwdLabel.textContent='—'; return; }
    if (s <= 1) { strengthBar.style.width='33%'; strengthBar.className='s-weak'; pwdLabel.textContent='Lemah'; }
    else if (s === 2 || s === 3) { strengthBar.style.width='66%'; strengthBar.className='s-medium'; pwdLabel.textContent='Sedang'; }
    else { strengthBar.style.width='100%'; strengthBar.className='s-strong'; pwdLabel.textContent='Kuat'; }
  }

  password.addEventListener('input', e => updateStrengthUI(e.target.value));
  password2.addEventListener('input', e => {
    if (password2.value !== password.value) {
      // small inline hint
      // we avoid showing full error until submit
    }
  });

  form.addEventListener('submit', async function(evt){
    evt.preventDefault();
    clearMsg();

    const vEmail = email.value.trim();
    const vName = displayName.value.trim();
    const vPwd = password.value;
    const vPwd2 = password2.value;

    // client validations
    if (!validateEmail(vEmail)) { showMsg('error','Alamat email tidak valid'); email.focus(); return; }
    if (vPwd.length < 8) { showMsg('error','Kata sandi minimal 8 karakter'); password.focus(); return; }
    if (vPwd !== vPwd2) { showMsg('error','Konfirmasi kata sandi tidak cocok'); password2.focus(); return; }

    // UI state
    submitBtn.disabled = true;
    submitBtn.textContent = 'Mendaftarkan...';

    try {
      const res = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify({ email: vEmail, password: vPwd, displayName: vName })
      });

      const j = await res.json();

      if (!res.ok) {
        // server returns structured errors from worker, such as { error: "user_exists" }
        const msg = (j && j.error) ? j.error : ('HTTP ' + res.status);
        showMsg('error', 'Gagal: ' + msg);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Buat Akun';
        return;
      }

      // success
      showMsg('success', 'Berhasil membuat akun!');
      // store token in cookie (same behavior as earlier UI)
      if (j && j.token) {
        // store cookie (not HttpOnly) for demo. In production, prefer server-set HttpOnly cookie.
        document.cookie = 'session=' + j.token + '; path=/; Secure; SameSite=Lax; Max-Age=' + (60*60*24*7);
      }

      // optional: redirect after brief delay
      setTimeout(() => {
        window.location.href = '/'; // atau ke dashboard
      }, 900);

    } catch (err) {
      showMsg('error', 'Terjadi kesalahan jaringan');
      console.error(err);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Buat Akun';
    }
  });

})();
</script>
</body>
</html>`;
