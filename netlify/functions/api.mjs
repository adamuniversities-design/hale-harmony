import { getStore } from "@netlify/blobs";
import { createHmac, createHash, timingSafeEqual, randomUUID } from "node:crypto";

export const TIMES = ["08:00", "09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00"];
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const isDate = (d) => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d) && new Date(d + "T12:00:00Z").toISOString().slice(0, 10) === d;
const dow = (d) => new Date(d + "T12:00:00Z").getUTCDay();
const isWork = (d) => isDate(d) && dow(d) >= 1 && dow(d) <= 5;
const addDays = (d, n) => { const x = new Date(d + "T12:00:00Z"); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
export const nowNL = () => { const p = {}; for (const x of new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Amsterdam", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date())) p[x.type] = x.value; return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour}:${p.minute}` }; };
const b64 = (s) => Buffer.from(s).toString("base64url");
const sig = (p, k) => createHmac("sha256", k).update(p).digest("base64url");
const mint = (k) => { const p = b64(JSON.stringify({ exp: Date.now() + 12 * 36e5 })); return `${p}.${sig(p, k)}`; };
const same = (a, b) => timingSafeEqual(createHash("sha256").update(String(a)).digest(), createHash("sha256").update(String(b)).digest());
const verify = (t, k) => { if (!t || !k) return false; const [p, s] = t.split("."); if (!p || !s || !same(s, sig(p, k))) return false; try { return JSON.parse(Buffer.from(p, "base64url").toString()).exp > Date.now(); } catch { return false; } };
const clean = (v, n) => String(v ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim().slice(0, n);
const taken = (db) => {
  const m = {}; const add = (d, t) => { (m[d] ||= new Set()); if (t == null) TIMES.forEach((x) => m[d].add(x)); else m[d].add(t); };
  db.blocks.forEach((b) => add(b.date, b.time ?? null));
  db.bookings.filter((b) => b.status !== "declined").forEach((b) => add(b.date, b.time));
  return m;
};

export async function handle(req, store, env) {
  const u = new URL(req.url), path = u.pathname.replace(/^\/api/, "").replace(/\/$/, ""), m = req.method;
  const get = async () => ({ bookings: (await store.get("bookings", { type: "json" })) || [], blocks: (await store.get("blocks", { type: "json" })) || [] });
  const body = async () => { try { return await req.json(); } catch { return {}; } };

  if (m === "GET" && path === "/availability") {
    const from = u.searchParams.get("from"), to = u.searchParams.get("to");
    if (!isDate(from) || !isDate(to) || to < from || addDays(from, 70) < to) return J({ error: "Ongeldige periode" }, 400);
    const t = taken(await get()), out = {};
    for (let d = from; d <= to; d = addDays(d, 1)) if (isWork(d) && t[d]) out[d] = [...t[d]];
    return J({ times: TIMES, taken: out, now: nowNL() });
  }

  if (m === "POST" && path === "/book") {
    const b = await body();
    if (b["bot-field"]) return J({ ok: true }, 201);
    const date = b.date, time = b.time, naam = clean(b.naam, 80), email = clean(b.email, 120);
    if (!isWork(date) || !TIMES.includes(time)) return J({ error: "Kies een geldig moment (ma t/m vr, 08:00 tot 16:00)." }, 400);
    if (!naam || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return J({ error: "Vul een naam en een geldig e-mailadres in." }, 400);
    if (b.leeftijd !== "ja" || b.toestemming !== "ja") return J({ error: "Bevestig je leeftijd en geef toestemming." }, 400);
    const n = nowNL();
    if (date < n.date || (date === n.date && time <= n.time) || date > addDays(n.date, 90)) return J({ error: "Dit moment kan niet worden gekozen." }, 400);
    const db = await get();
    if (taken(db)[date]?.has(time)) return J({ error: "Dit tijdstip is helaas niet meer beschikbaar." }, 409);
    if (db.bookings.length > 2000) return J({ error: "Tijdelijk niet beschikbaar" }, 503);
    db.bookings.push({ id: randomUUID(), date, time, naam, email, telefoon: clean(b.telefoon, 30), contactvoorkeur: clean(b.contactvoorkeur, 20), onderwerp: (Array.isArray(b.onderwerp) ? b.onderwerp : [b.onderwerp]).filter(Boolean).map((x) => clean(x, 60)).slice(0, 6), vorm: clean(b.vorm, 20), toelichting: clean(b.toelichting, 1000), status: "pending", createdAt: new Date().toISOString() });
    await store.setJSON("bookings", db.bookings);
    return J({ ok: true }, 201);
  }

  if (m === "POST" && path === "/admin/login") {
    const b = await body();
    if (!env.ADMIN_PASSWORD || !env.ADMIN_SECRET) return J({ error: "Beheer is nog niet ingesteld" }, 500);
    if (!same(b.password ?? "", env.ADMIN_PASSWORD)) { await new Promise((r) => setTimeout(r, 800)); return J({ error: "Onjuist wachtwoord" }, 401); }
    return J({ token: mint(env.ADMIN_SECRET) });
  }

  if (path.startsWith("/admin/")) {
    if (!verify((req.headers.get("authorization") || "").replace(/^Bearer /, ""), env.ADMIN_SECRET)) return J({ error: "Niet ingelogd" }, 401);
    const db = await get();
    if (m === "GET" && path === "/admin/data") return J(db);
    if (m === "POST") {
      const b = await body();
      if (path === "/admin/status") {
        const x = db.bookings.find((y) => y.id === b.id);
        if (!x || !["pending", "confirmed", "declined"].includes(b.status)) return J({ error: "Ongeldig" }, 400);
        if (b.status !== "declined" && x.status === "declined" && taken(db)[x.date]?.has(x.time)) return J({ error: "Dit tijdstip is inmiddels bezet" }, 409);
        x.status = b.status; await store.setJSON("bookings", db.bookings); return J({ ok: true });
      }
      if (path === "/admin/block" || path === "/admin/unblock") {
        if (!isWork(b.date) || (b.time != null && !TIMES.includes(b.time))) return J({ error: "Ongeldig" }, 400);
        const t = b.time ?? null;
        if (path === "/admin/block") { if (!db.blocks.some((z) => z.date === b.date && (z.time ?? null) === t)) db.blocks.push({ date: b.date, time: t }); }
        else db.blocks = db.blocks.filter((z) => !(z.date === b.date && (t === null || (z.time ?? null) === t)));
        await store.setJSON("blocks", db.blocks); return J({ ok: true });
      }
      if (path === "/admin/delete") { db.bookings = db.bookings.filter((y) => y.id !== b.id); await store.setJSON("bookings", db.bookings); return J({ ok: true }); }
    }
    return J({ error: "Niet gevonden" }, 404);
  }
  return J({ error: "Niet gevonden" }, 404);
}

export default async (req) => {
  try { return await handle(req, getStore("hale"), { ADMIN_PASSWORD: Netlify.env.get("ADMIN_PASSWORD"), ADMIN_SECRET: Netlify.env.get("ADMIN_SECRET") }); }
  catch (e) { console.error(e); return J({ error: "Er ging iets mis" }, 500); }
};
export const config = { path: "/api/*" };
