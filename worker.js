// Updated handleLogin supporting JSON OR form-urlencoded bodies (no JS required)
async function handleLogin(req) {
  // Accept JSON or form-urlencoded
  let body = {};
  const ct = (req.headers.get("Content-Type") || "").split(";")[0].trim();

  if (ct === "application/json") {
    body = await req.json().catch(()=>({}));
  } else if (ct === "application/x-www-form-urlencoded") {
    const text = await req.text().catch(()=>"");
    // parse urlencoded
    body = Object.fromEntries(new URLSearchParams(text));
  } else {
    // try json fallback
    body = await req.json().catch(()=>{ 
      // as last resort parse text as querystring
      const t = (await req.text().catch(()=>""));
      return Object.fromEntries(new URLSearchParams(t));
    });
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
  
  // If request comes from a browser form submit (no JS), we should redirect after login.
  // We detect HTML form by checking Accept header includes text/html and Content-Type is form.
  const accept = (req.headers.get("Accept") || "");
  const isForm = ct === "application/x-www-form-urlencoded" || ct === "multipart/form-data";
  const wantsHtml = accept.includes("text/html") || accept.includes("application/xhtml+xml");

  if (isForm && wantsHtml) {
    // redirect to home after setting cookie
    return new Response(null, {
      status: 303,
      headers: {
        "Set-Cookie": cookie,
        "Location": "/"
      }
    });
  }

  // otherwise return JSON (for API / fetch usage)
  return new Response(JSON.stringify({ ok: true, token }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie }
  });
}
