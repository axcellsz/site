export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname.replace(/\/+$/, ""); // remove trailing slash
      if (request.method === "GET" && pathname === "/get") {
        const key = url.searchParams.get("key");
        if (!key) return jsonResponse({ error: "missing key" }, 400);
        const value = await env.MY_KV.get(key, { type: "text" });
        if (value === null) return jsonResponse({ error: "not_found" }, 404);
        return jsonResponse({ key, value });
      }

      if (request.method === "POST" && pathname === "/set") {
        // Accept JSON body { key, value } or form/urlencoded or query params fallback
        let key, value;
        const ct = request.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          const body = await request.json();
          key = body.key;
          value = body.value;
        } else if (ct.includes("application/x-www-form-urlencoded")) {
          const form = await request.formData();
          key = form.get("key");
          value = form.get("value");
        } else {
          // fallback to query params
          const url = new URL(request.url);
          key = url.searchParams.get("key");
          value = url.searchParams.get("value");
        }

        if (!key || value === undefined || value === null) {
          return jsonResponse({ error: "missing key or value" }, 400);
        }

        // optional: enforce small size; KV supports up to 25MB per value but keep small
        await env.MY_KV.put(key, String(value));
        return jsonResponse({ ok: true, key });
      }

      if (request.method === "DELETE" && pathname === "/delete") {
        const key = url.searchParams.get("key");
        if (!key) return jsonResponse({ error: "missing key" }, 400);
        await env.MY_KV.delete(key);
        return jsonResponse({ ok: true, key });
      }

      if (request.method === "GET" && pathname === "/list") {
        // list keys with optional prefix and limit
        const prefix = url.searchParams.get("prefix") || undefined;
        const limit = Number(url.searchParams.get("limit") || 100);
        // KV list has a hard max (1000); enforce safety
        const safeLimit = Math.min(Math.max(1, limit || 100), 1000);
        const listResult = await env.MY_KV.list({ prefix, limit: safeLimit });
        // listResult.keys => array of { name, metadata }
        return jsonResponse({ keys: listResult.keys, list_complete: listResult.list_complete });
      }

      // Default: show simple help
      return new Response(HELP_TEXT, {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    } catch (err) {
      return jsonResponse({ error: "internal_error", message: String(err) }, 500);
    }
  }
};

// small helpers
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

const HELP_TEXT = `
KV Worker endpoints:

GET  /get?key=KEY            -> { key, value }
POST /set  (JSON or form)   -> { ok: true, key }
DELETE /delete?key=KEY      -> { ok: true, key }
GET  /list?prefix=&limit=   -> { keys: [...] }

Use Content-Type: application/json with body {"key":"k","value":"v"} for POST /set
`.trim();
