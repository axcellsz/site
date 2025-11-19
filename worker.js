export default {
  async fetch(request, env) {

    // Tulis KV
    await env.MY_KV.put("hello", "world");

    // Baca KV
    const value = await env.MY_KV.get("hello");

    return new Response("KV result: " + value, {
      headers: { "Content-Type": "text/plain" }
    });
  }
};
