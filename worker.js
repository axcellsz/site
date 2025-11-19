addEventListener("fetch", event => {
  event.respondWith(new Response("OK - worker alive", {
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  }));
});
