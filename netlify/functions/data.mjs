import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";

export default async (req) => {
  const code = req.headers.get("x-sync-code") || "";
  if (code.length < 8) return new Response("Invalid sync code", { status: 401 });
  const key = createHash("sha256").update(code).digest("hex");
  const store = getStore("spendly");

  if (req.method === "GET") {
    return Response.json((await store.get(key, { type: "json" })) || null);
  }
  if (req.method === "PUT") {
    const body = await req.json();
    if (!body || !Array.isArray(body.expenses)) return new Response("Bad data", { status: 400 });
    await store.setJSON(key, body);
    return Response.json({ ok: true });
  }
  return new Response("Method not allowed", { status: 405 });
};

export const config = { path: "/api/data" };
