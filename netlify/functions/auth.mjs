import { users, userKey, normUser, hashPw, checkPw, ensureSeed, newSession, userFromReq, dropSession } from "../lib/auth.mjs";
import { randomBytes } from "node:crypto";

const json = (o, status = 200) => Response.json(o, { status });
const fail = (msg, status = 400) => json({ error: msg }, status);

export default async (req) => {
  if (req.method !== "POST") return fail("Method not allowed", 405);
  await ensureSeed();
  let b;
  try { b = await req.json(); } catch { return fail("Bad request"); }

  if (b.action === "signup") {
    const name = String(b.name || "").trim(), username = normUser(b.username), password = String(b.password || "");
    if (!name || name.length > 40) return fail("Enter your name (max 40 characters).");
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) return fail("Username: 3-30 letters, numbers, . _ -");
    if (password.length < 8) return fail("Password must be at least 8 characters.");
    if (await users().get(userKey(username))) return fail("That username is already taken.", 409);
    const salt = randomBytes(16).toString("hex");
    await users().setJSON(userKey(username), { username, name, salt, hash: hashPw(password, salt) });
    return json({ token: await newSession(username), username, name });
  }
  if (b.action === "login") {
    const username = normUser(b.username), password = String(b.password || "");
    const u = await users().get(userKey(username), { type: "json" });
    if (!u || !checkPw(password, u.salt, u.hash)) {
      await new Promise((r) => setTimeout(r, 400));
      return fail("Wrong username or password.", 401);
    }
    return json({ token: await newSession(u.username), username: u.username, name: u.name });
  }
  if (b.action === "me") {
    const u = await userFromReq(req);
    return u ? json({ username: u.username, name: u.name }) : fail("Not signed in", 401);
  }
  if (b.action === "logout") {
    const u = await userFromReq(req);
    if (u) await dropSession(u.token);
    return json({ ok: true });
  }
  return fail("Unknown action");
};

export const config = { path: "/api/auth" };
