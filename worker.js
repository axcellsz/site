// Updated handleLogin — safe (no await inside non-async callback)
async function handleLogin(req) {
  // Accept JSON or form-urlencoded
  let body = {};
  const ct = (req.headers.get("Content-Type") || "").split(";")[0].trim();

  if (ct === "application/json") {
    body = await req.json().catch(() => ({}));
  } else if (ct === "application/x-www-form-urlencoded") {
    const text = await req.text().catch(() => "");
    body = Object.fromEntries(new URLSearchParams(text));
  } else {
    // try json fallback, then fallback to urlencoded parsing
    try {
      body = await req.json();
    } catch (e) {
      const text = await req.text().catch(() => "");
      body = Object.fromEntries(new URLSearchParams(text));
    }
  }

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
  
  // detect HTML form submit -> redirect
  const accept = (req.headers.get("Accept") || "");
  const isForm = ct === "application/x-www-form-urlencoded" || ct.startsWith("multipart/form-data");
  const wantsHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");

  if (isForm && wantsHtml) {
    return new Response(null, {
      status: 303,
      headers: {
        "Set-Cookie": cookie,
        "Location": "/"
      }
    });
  }

  return new Response(JSON.stringify({ ok: true, token }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
  });
}
