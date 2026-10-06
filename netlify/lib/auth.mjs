import { getStore } from "@netlify/blobs";
import { randomBytes, scryptSync, timingSafeEqual, createHash } from "node:crypto";

export const users = () => getStore("spendly-users");
export const sessions = () => getStore("spendly-sessions");
export const dataStore = () => getStore("spendly");

const sha = (s) => createHash("sha256").update(s).digest("hex");
export const hashPw = (pw, salt) => scryptSync(pw, salt, 64).toString("hex");
export const checkPw = (pw, salt, hash) => {
  const a = Buffer.from(hashPw(pw, salt), "hex"), b = Buffer.from(hash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
};
export const normUser = (u) => String(u || "").trim().toLowerCase();
export const userKey = (u) => "u:" + sha(normUser(u));
export const dataKey = (u) => "user:" + sha(normUser(u));

// Account created for the site owner (password stored only as a salted scrypt hash).
const SEED = [{
  username: "maizamisman", name: "maiza",
  salt: "46d0250e96546bda284648fc10ef894a",
  hash: "410900fa6e15e54818ce9e53611a9917c6ad3e76af836a3d4a7c25d28b3099937e1c62c47150ab285a95fbe3a94b17d2bf4c2e375094863c0ebc72988f3402d7",
}];
export async function ensureSeed() {
  for (const s of SEED) {
    const k = userKey(s.username);
    if (!(await users().get(k))) await users().setJSON(k, s);
  }
}

const SESSION_MS = 365 * 24 * 3600 * 1000;
export async function newSession(username) {
  const token = randomBytes(32).toString("hex");
  await sessions().setJSON(sha(token), { username, exp: Date.now() + SESSION_MS });
  return token;
}
export async function userFromReq(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  const s = await sessions().get(sha(m[1]), { type: "json" });
  if (!s || s.exp < Date.now()) return null;
  const u = await users().get(userKey(s.username), { type: "json" });
  return u ? { username: u.username, name: u.name, token: m[1] } : null;
}
export const dropSession = (token) => sessions().delete(sha(token));
export const legacyKey = (code) => sha(code);
