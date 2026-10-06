import { dataStore, dataKey, userFromReq, legacyKey } from "../lib/auth.mjs";

export default async (req) => {
  const user = await userFromReq(req);
  if (!user) return new Response("Not signed in", { status: 401 });
  const store = dataStore();

  if (req.method === "GET") {
    // one-time import of data saved under the old private sync code
    const legacy = new URL(req.url).searchParams.get("legacy");
    if (legacy) {
      const code = req.headers.get("x-sync-code") || "";
      if (code.length < 8) return Response.json(null);
      return Response.json((await store.get(legacyKey(code), { type: "json" })) || null);
    }
    return Response.json((await store.get(dataKey(user.username), { type: "json" })) || null);
  }
  if (req.method === "PUT") {
    const body = await req.json();
    if (!body || !Array.isArray(body.expenses)) return new Response("Bad data", { status: 400 });
    await store.setJSON(dataKey(user.username), body);
    return Response.json({ ok: true });
  }
  return new Response("Method not allowed", { status: 405 });
};

export const config = { path: "/api/data" };
