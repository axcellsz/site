// ---------- API: register (supports JSON and form)
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
  const ttl = 60*60*24*7;
  await kvPut(`sess:${token}`, { username, createdAt: new Date().toISOString() }, { expirationTtl: ttl });
  const cookie = `session=${token}; HttpOnly; Path=/; Max-Age=${ttl}; SameSite=Lax; Secure`;

  // If form submission and wants HTML, redirect to login page (with flag)
  const accept = (req.headers.get("Accept") || "");
  const isForm = (req.headers.get("Content-Type") || "").split(";")[0].trim().startsWith("application/x-www-form-urlencoded");
  const wantsHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");
  if (isForm && wantsHtml) {
    // redirect to login page and inform success via query string
    return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, "Location": "/login.html?registered=1" }});
  }

  // API JSON response
  return new Response(JSON.stringify({ ok:true, token }), { status:200, headers: { "Content-Type":"application/json", "Set-Cookie": cookie }});
}
