addEventListener("fetch", event => {
  event.respondWith(handle(event.request, event));
});

async function handle(req, event) {
  const env = event.target.env; // Cloudflare mengisi env ke sini secara internal

  // Tulis ke KV
  await env.MY_KV.put("hello", "world");

  // Baca dari KV
  const value = await env.MY_KV.get("hello");

  return new Response("KV result: " + value, {
    status: 200,
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  });
}
