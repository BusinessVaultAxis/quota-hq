// Quota HQ server: email + password logins, role-based data, Postgres storage.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.createHash("sha256").update("qhq:" + (process.env.DATABASE_URL || crypto.randomBytes(32).toString("hex"))).digest("hex");
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const SECURE = BASE_URL.startsWith("https");
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === "1" ? { rejectUnauthorized: false } : undefined });
const COLS = ["reps", "rates", "sales", "expenses", "incentives", "goals", "reviews", "partners", "crews", "territories"];
const EXP_CATS = ["Flights", "Housing", "Hotel", "Rental car", "Gas", "Food", "Tickets & events", "Supplies", "Other"];

/* ---------- db ---------- */
async function init() {
  await pool.query(`create table if not exists docs(col text not null, id text not null, data jsonb not null, updated timestamptz default now(), primary key(col,id))`);
  await pool.query(`create table if not exists users(id serial primary key, email text unique not null, pw text, role text not null default 'rep', rep_id text, invite text, invite_exp timestamptz, created timestamptz default now(), last_login timestamptz)`);
  await pool.query(`create table if not exists recruit_codes(rep_id text primary key, code text unique not null)`);
  await pool.query(`create table if not exists applicants(id serial primary key, recruiter text, name text not null, phone text, email text, market text, status text not null default 'pending', created timestamptz default now())`);
  await pool.query(`create table if not exists prefs(user_id int primary key, data jsonb not null default '{}')`);
  const { rows: cnt } = await pool.query(`select count(*)::int n from docs`);
  const seedF = path.join(__dirname, "data", "seed.json");
  if (!cnt[0].n && fs.existsSync(seedF)) {
    const S = JSON.parse(fs.readFileSync(seedF, "utf8")); let n = 0;
    for (const c of Object.keys(S)) for (const id of Object.keys(S[c])) { await pool.query(`insert into docs(col,id,data) values($1,$2,$3) on conflict do nothing`, [c, id, JSON.stringify(S[c][id])]); n++ }
    console.log(`Seeded ${n} records`);
  }
  await pool.query(`create table if not exists applied_syncs(name text primary key, at timestamptz default now())`);
  const syncDir = path.join(__dirname, "data", "sync");
  if (fs.existsSync(syncDir)) for (const f of fs.readdirSync(syncDir).filter(f => f.endsWith(".json")).sort()) {
    if ((await pool.query(`select 1 from applied_syncs where name=$1`, [f])).rows[0]) continue;
    const ops = JSON.parse(fs.readFileSync(path.join(syncDir, f), "utf8")); let n = 0;
    for (const o of ops) {
      if (o.set) { await pool.query(`insert into docs(col,id,data) values($1,$2,$3) on conflict(col,id) do nothing`, [o.col, o.id, JSON.stringify(o.set)]); n++ }
      else if (o.patch) { const r = await pool.query(`update docs set data=data||$3,updated=now() where col=$1 and id=$2`, [o.col, o.id, JSON.stringify(o.patch)]); n += r.rowCount }
    }
    await pool.query(`insert into applied_syncs(name) values($1)`, [f]); console.log(`Applied ${f}: ${n} changes`);
  }
  if (ADMIN_EMAIL) {
    const { rows } = await pool.query(`select id,pw,invite,invite_exp>now() as live from users where role='admin'`);
    if (rows[0] && !rows[0].pw && rows[0].invite && rows[0].live) console.log(`ADMIN SETUP LINK: ${BASE_URL}/invite/${rows[0].invite}`);
    if (!rows.length) {
      const t = token();
      await pool.query(`insert into users(email,role,rep_id,invite,invite_exp) values($1,'admin',(select id from docs where col='reps' and (data->>'me')::boolean is true limit 1),$2,now()+interval '7 days') on conflict(email) do update set role='admin',invite=$2,invite_exp=now()+interval '7 days'`, [ADMIN_EMAIL, t]);
      console.log(`ADMIN SETUP LINK: ${BASE_URL}/invite/${t}`);
    } else if (!rows[0].pw && !rows[0].live) {
      const t = token();
      await pool.query(`update users set invite=$1,invite_exp=now()+interval '7 days' where id=$2`, [t, rows[0].id]);
      console.log(`ADMIN SETUP LINK: ${BASE_URL}/invite/${t}`);
    }
  }
}
const all = async c => (await pool.query(`select id,data from docs where col=$1`, [c])).rows.map(r => Object.assign({}, r.data, { id: r.id }));

/* ---------- auth ---------- */
const token = () => crypto.randomBytes(24).toString("base64url");
const hashPw = pw => new Promise((res, rej) => { const salt = crypto.randomBytes(16); crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(salt.toString("hex") + ":" + k.toString("hex"))) });
const checkPw = (pw, h) => new Promise(res => { if (!h) return res(false); const [s, k] = h.split(":"); crypto.scrypt(pw, Buffer.from(s, "hex"), 64, (e, d) => res(!e && crypto.timingSafeEqual(d, Buffer.from(k, "hex")))) });
const sign = v => crypto.createHmac("sha256", SECRET).update(v).digest("base64url");
const makeSession = uid => { const v = `${uid}.${Date.now() + 30 * 864e5}`; return `${v}.${sign(v)}` };
function readSession(req) {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)qhq=([^;]+)/); if (!m) return null;
  const [uid, exp, sig] = m[1].split("."); const v = `${uid}.${exp}`;
  if (!sig || sig.length !== sign(v).length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(v))) || +exp < Date.now()) return null;
  return +uid;
}
const cookie = (v, age) => `qhq=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${SECURE ? "; Secure" : ""}`;
async function currentUser(req) { const id = readSession(req); if (!id) return null; const { rows } = await pool.query(`select id,email,role,rep_id from users where id=$1 and pw is not null`, [id]); return rows[0] || null }
const tries = new Map();
function limited(key) { const n = Date.now(), a = (tries.get(key) || []).filter(t => n - t < 15 * 60e3); a.push(n); tries.set(key, a); return a.length > 10 }

/* ---------- pay math (mirrors the app) ---------- */
const num = v => { const n = parseFloat(v); return isFinite(n) ? n : 0 };
const qty = s => Math.max(1, num(s.qty) || 1);
function hydrate(D) {
  const byId = {}, QS = {}; D.reps.forEach(r => { byId[r.id] = r; if (r.quotaStart) QS[r.id] = r.quotaStart });
  const top = D.reps.find(r => r.me), topSc = top && num(top.scale) ? num(top.scale) : 300;
  const sc = (r, d) => { if (!r) return null; if (num(r.scale2) && r.scale2From && d >= r.scale2From) return num(r.scale2); return num(r.scale) ? num(r.scale) : null };
  const findRate = (type, prov, prod, repId) => { const m = r => (r.category || "fiber") === type && String(r.provider).toLowerCase() === String(prov).toLowerCase() && String(r.product).toLowerCase() === String(prod).toLowerCase(); return D.rates.find(r => m(r) && r.repId === repId) || D.rates.find(r => m(r) && !r.repId) };
  return D.sales.map(s => {
    const q = QS[s.repId]; if (q && (s.date || "") < q) return null;
    const rt = findRate(s.type || "fiber", s.provider, s.product, s.repId), rev = (s.revenue !== undefined && s.revenue !== null && s.revenue !== "") ? num(s.revenue) : (rt ? num(rt.revenue) : 0);
    const d = (s.status === "done" && (s.installDate || s.date)) || s.date || "", delta = rev - topSc, chain = [], seen = new Set(); let r = byId[s.repId];
    while (r && !seen.has(r.id)) { seen.add(r.id); chain.push(r); r = byId[r.managerId] }
    const ss = sc(chain[0], d), ovr = {}; let rp = 0;
    if (ss != null) { rp = Math.max(0, ss + delta); let prev = ss; for (let i = 1; i < chain.length; i++) { const a = sc(chain[i], d); if (a == null) break; if (a - prev > 0) ovr[chain[i].id] = a - prev; prev = a } }
    return Object.assign({}, s, { revenue: rev, repPay: rp, ovr, scaleKnown: ss != null });
  }).filter(Boolean);
}

/* ---------- data views ---------- */
async function dataFor(u) {
  const D = {}; for (const c of COLS) D[c] = await all(c);
  const pr = (await pool.query(`select data from prefs where user_id=$1`, [u.id])).rows[0];
  if (u.role === "admin") { const rg = {}; (await pool.query(`select u.rep_id,p.data from prefs p join users u on u.id=p.user_id where u.rep_id is not null and u.role='rep'`)).rows.forEach(r => { rg[r.rep_id] = r.data }); D._repGoals = rg }
  if (u.role === "admin") return Object.assign(D, { _me: { id: "u" + u.id, email: u.email, role: "admin", prefs: pr ? pr.data : {} } });
  if (u.role === "manager") return Object.assign(D, { _repGoals: null, _me: { id: "u" + u.id, email: u.email, role: "manager", prefs: {} } });
  // rep: only what a rep should see
  const me = u.rep_id, sales = hydrate(D), now = new Date(), ms = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  const kids = {}; D.reps.forEach(r => { (kids[r.managerId] = kids[r.managerId] || []).push(r.id) });
  const down = new Set(); (function walk(id) { (kids[id] || []).forEach(k => { if (!down.has(k)) { down.add(k); walk(k) } }) })(me);
  const teamMonthRev = sales.filter(s => s.status === "done" && (s.installDate || s.date || "").startsWith(ms)).reduce((a, s) => a + s.revenue * qty(s), 0);
  const reps = D.reps.map(r => { const o = { id: r.id, name: r.name, managerId: r.managerId, team: r.team, role: r.role, status: r.status }; if (r.id === me) Object.assign(o, { scale: r.scale, scale2: r.scale2, scale2From: r.scale2From, email: u.email, userId: "u" + u.id }); return o });
  const out = sales.map(s => {
    const o = { id: s.id, repId: s.repId, date: s.date, installDate: s.installDate, status: s.status, type: s.type, qty: s.qty, provider: s.provider, product: s.product, scaleKnown: s.scaleKnown, ovr: {} };
    if (s.repId === me) Object.assign(o, { customer: s.customer, notes: s.notes, repPay: s.repPay, paid: s.paid });
    if (s.ovr[me]) o.ovr[me] = s.ovr[me];
    if (down.has(s.repId)) o.customer = s.customer;
    return o;
  });
  const goals = D.goals.filter(g => g.id === "main").map(g => Object.assign({}, g, { _teamMonthRev: teamMonthRev }));
  const myTeam = (D.reps.find(r => r.id === me) || {}).team || "", myCrews = new Set(D.crews.filter(c => c.name === myTeam).map(c => c.id));
  const territories = D.territories.filter(t => (t.repIds || []).includes(me) || (t.crewId && myCrews.has(t.crewId))).map(t => ({ id: t.id, isp: t.isp, city: t.city, start: t.start, end: t.end, aNote: t.aNote, leads: t.leads, repIds: [me] }));
  return { reps, sales: out, rates: [], expenses: [], incentives: D.incentives, goals, territories, partners: [], crews: [], _pre: true, _me: { id: "u" + u.id, email: u.email, role: "rep", repId: me, prefs: pr ? pr.data : {} } };
}

/* ---------- http ---------- */
const send = (res, code, body, headers = {}) => { res.writeHead(code, Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store" }, headers)); res.end(typeof body === "string" ? body : JSON.stringify(body)) };
const body = req => new Promise((res, rej) => { let b = ""; req.on("data", c => { b += c; if (b.length > 2e6) req.destroy() }); req.on("end", () => { try { res(b ? JSON.parse(b) : {}) } catch (e) { rej(e) } }) });
const page = name => fs.readFileSync(path.join(__dirname, "public", name));
const SEC_HEADERS = { "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin" };
const html = (res, name) => { res.writeHead(200, Object.assign({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }, SEC_HEADERS)); res.end(page(name)) };
const validId = s => typeof s === "string" && /^[A-Za-z0-9_\-.~:@+]{1,200}$/.test(s);

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, BASE_URL), p = url.pathname, m = req.method;
    if (m !== "GET" && m !== "HEAD" && !(req.headers["content-type"] || "").includes("application/json")) return send(res, 415, { error: "json only" });
    // pages
    if (m === "GET" && p === "/health") return send(res, 200, { ok: true });
    if (m === "GET" && (p === "/login" || p.startsWith("/invite/"))) return html(res, "login.html");
    if (m === "GET" && p.startsWith("/join/")) return html(res, "join.html");
    if (m === "GET" && p.startsWith("/api/join/")) {
      const { rows } = await pool.query(`select d.data->>'name' as name from recruit_codes c join docs d on d.col='reps' and d.id=c.rep_id where c.code=$1`, [p.split("/")[3]]);
      return rows[0] ? send(res, 200, { recruiter: rows[0].name }) : send(res, 404, { error: "This invite link isn't valid. Ask whoever sent it for a new one." });
    }
    if (m === "POST" && p === "/api/join") {
      if (limited("join:" + (req.headers["x-forwarded-for"] || req.socket.remoteAddress))) return send(res, 429, { error: "Too many tries. Wait 15 minutes." });
      const b = await body(req), name = String(b.name || "").trim().slice(0, 80), phone = String(b.phone || "").trim().slice(0, 30), email = String(b.email || "").trim().toLowerCase().slice(0, 120), market = String(b.market || "").trim().slice(0, 80);
      if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || phone.replace(/\D/g, "").length < 10) return send(res, 400, { error: "Add your full name, a real phone number and email." });
      const { rows } = await pool.query(`select rep_id from recruit_codes where code=$1`, [String(b.code || "")]);
      if (!rows[0]) return send(res, 404, { error: "This invite link isn't valid. Ask whoever sent it for a new one." });
      const dup = await pool.query(`select 1 from applicants where email=$1 and status='pending'`, [email]);
      if (!dup.rows[0]) await pool.query(`insert into applicants(recruiter,name,phone,email,market) values($1,$2,$3,$4,$5)`, [rows[0].rep_id, name, phone, email, market]);
      return send(res, 200, { ok: true });
    }
    if (m === "GET" && p === "/logo.svg") { res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "max-age=86400" }); return res.end(page("logo.svg")) }
    if (m === "GET" && p === "/") { const u = await currentUser(req); if (!u) { res.writeHead(302, { Location: "/login" }); return res.end() } return html(res, "index.html") }

    // auth api
    if (m === "POST" && p === "/api/login") {
      const b = await body(req), email = String(b.email || "").trim().toLowerCase();
      if (limited("ip:" + (req.headers["x-forwarded-for"] || req.socket.remoteAddress)) || limited("e:" + email)) return send(res, 429, { error: "Too many tries. Wait 15 minutes." });
      const { rows } = await pool.query(`select id,pw from users where email=$1`, [email]);
      if (!rows[0] || !(await checkPw(String(b.password || ""), rows[0].pw))) return send(res, 401, { error: "Email or password is wrong." });
      await pool.query(`update users set last_login=now() where id=$1`, [rows[0].id]);
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie(makeSession(rows[0].id), 30 * 86400) });
    }
    if (m === "POST" && p === "/api/logout") return send(res, 200, { ok: true }, { "Set-Cookie": cookie("", 0) });
    if (m === "GET" && p.startsWith("/api/invite/")) {
      const t = p.split("/")[3]; const { rows } = await pool.query(`select u.email,u.rep_id,d.data->>'name' as name from users u left join docs d on d.col='reps' and d.id=u.rep_id where invite=$1 and invite_exp>now()`, [t]);
      return rows[0] ? send(res, 200, { email: rows[0].email, name: rows[0].name || "" }) : send(res, 404, { error: "This link expired or was already used. Ask Aidan for a new one." });
    }
    if (m === "POST" && p === "/api/invite/accept") {
      const b = await body(req), pw = String(b.password || "");
      if (pw.length < 8) return send(res, 400, { error: "Use at least 8 characters." });
      const { rows } = await pool.query(`update users set pw=$1,invite=null,invite_exp=null,last_login=now() where invite=$2 and invite_exp>now() returning id`, [await hashPw(pw), String(b.token || "")]);
      if (!rows[0]) return send(res, 404, { error: "This link expired or was already used. Ask Aidan for a new one." });
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie(makeSession(rows[0].id), 30 * 86400) });
    }

    // everything below needs a login
    if (!p.startsWith("/api/")) return send(res, 404, { error: "not found" });
    const u = await currentUser(req); if (!u) return send(res, 401, { error: "Sign in again." });
    if (m === "GET" && p === "/api/data") return send(res, 200, await dataFor(u));
    if (m === "PUT" && p === "/api/prefs") { const b = await body(req); await pool.query(`insert into prefs(user_id,data) values($1,$2) on conflict(user_id) do update set data=prefs.data||$2`, [u.id, JSON.stringify(Object.fromEntries([["goalType", ["pay", "sales", "installs"].includes(b.goalType) ? b.goalType : undefined], ...["payGoal", "salesGoal", "installGoal"].map(k => [k, b[k] !== undefined ? num(b[k]) : undefined])].filter(x => x[1] !== undefined)))]); return send(res, 200, { ok: true }) }

    if (m === "GET" && p === "/api/recruit-link") {
      if (!u.rep_id) return send(res, 400, { error: "Your login isn't tied to a rep yet." });
      let { rows } = await pool.query(`select code from recruit_codes where rep_id=$1`, [u.rep_id]);
      if (!rows[0]) { const c = crypto.randomBytes(5).toString("base64url"); await pool.query(`insert into recruit_codes(rep_id,code) values($1,$2) on conflict(rep_id) do nothing`, [u.rep_id, c]); rows = (await pool.query(`select code from recruit_codes where rep_id=$1`, [u.rep_id])).rows }
      return send(res, 200, { link: `${BASE_URL}/join/${rows[0].code}` });
    }

    // manager: read everything, add expenses and mark payouts reviewed
    if (u.role === "manager") {
      const mm = p.match(/^\/api\/doc\/(expenses|reviews)(?:\/([^/]+))?$/);
      if (!mm) return send(res, 403, { error: "Managers can add expenses and review payouts only." });
      const col = mm[1], id = mm[2] ? decodeURIComponent(mm[2]) : crypto.randomBytes(10).toString("hex"); if (!validId(id)) return send(res, 400, { error: "bad id" });
      const cur = (await pool.query(`select data from docs where col=$1 and id=$2`, [col, id])).rows[0];
      if (col === "expenses" && cur && cur.data.byUser !== u.id) return send(res, 403, { error: "You can only change expenses you added." });
      if (m === "DELETE") { await pool.query(`delete from docs where col=$1 and id=$2`, [col, id]); return send(res, 200, { ok: true }) }
      const b = await body(req); delete b.id;
      if (col === "expenses") {
        if (!EXP_CATS.includes(b.category)) return send(res, 400, { error: "Pick a category." });
        if (!(num(b.amount) > 0)) return send(res, 400, { error: "Add the amount." });
        if (String(b.note || "").trim().length < 3) return send(res, 400, { error: "Say what the expense was for." });
        Object.assign(b, { byUser: u.id, by: u.email });
      } else Object.assign(b, { by: u.email, at: new Date().toISOString() });
      const data = m === "PATCH" && cur ? Object.assign({}, cur.data, b) : b;
      await pool.query(`insert into docs(col,id,data) values($1,$2,$3) on conflict(col,id) do update set data=$3,updated=now()`, [col, id, JSON.stringify(data)]);
      return send(res, 200, { ok: true, id });
    }
    if (u.role !== "admin") return send(res, 403, { error: "Admins only." });
    if (m === "GET" && p === "/api/applicants") { const { rows } = await pool.query(`select a.*,d.data->>'name' as recruiter_name from applicants a left join docs d on d.col='reps' and d.id=a.recruiter where a.status='pending' order by a.created`); return send(res, 200, rows) }
    const am = p.match(/^\/api\/applicants\/(\d+)(\/approve)?$/);
    if (am && m === "DELETE") { await pool.query(`update applicants set status='declined' where id=$1`, [+am[1]]); return send(res, 200, { ok: true }) }
    if (am && am[2] && m === "POST") {
      const b = await body(req), { rows } = await pool.query(`select * from applicants where id=$1 and status='pending'`, [+am[1]]); const a = rows[0];
      if (!a) return send(res, 404, { error: "Already handled." });
      const scale = num(b.scale); if (!scale) return send(res, 400, { error: "Set a pay scale first." });
      let id = a.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "rep";
      if ((await pool.query(`select 1 from docs where col='reps' and id=$1`, [id])).rows[0]) id += "-" + crypto.randomBytes(2).toString("hex");
      const mgr = (await pool.query(`select data from docs where col='reps' and id=$1`, [a.recruiter])).rows[0];
      const rep = { name: a.name, phone: a.phone, email: a.email, market: a.market || "", managerId: a.recruiter, scale, role: "Rep", status: "Onboarding", team: (mgr && mgr.data.team) || "Team Quota", me: false, isps: "", joined: new Date().toISOString().slice(0, 10) };
      await pool.query(`insert into docs(col,id,data) values('reps',$1,$2)`, [id, JSON.stringify(rep)]);
      const t = token(); await pool.query(`insert into users(email,role,rep_id,invite,invite_exp) values($1,'rep',$2,$3,now()+interval '7 days') on conflict(email) do update set rep_id=$2,invite=$3,invite_exp=now()+interval '7 days'`, [a.email, id, t]);
      await pool.query(`update applicants set status='approved' where id=$1`, [a.id]);
      return send(res, 200, { repId: id, link: `${BASE_URL}/invite/${t}` });
    }
    // admin: documents
    const dm = p.match(/^\/api\/doc\/([a-z]+)(?:\/([^/]+))?$/);
    if (dm) {
      const [, col, rawId] = dm; if (!COLS.includes(col)) return send(res, 400, { error: "bad collection" });
      const id = rawId ? decodeURIComponent(rawId) : crypto.randomBytes(10).toString("hex"); if (!validId(id)) return send(res, 400, { error: "bad id" });
      if (m === "DELETE") { await pool.query(`delete from docs where col=$1 and id=$2`, [col, id]); return send(res, 200, { ok: true }) }
      const b = await body(req); delete b.id;
      if (m === "PUT" || m === "POST") await pool.query(`insert into docs(col,id,data) values($1,$2,$3) on conflict(col,id) do update set data=$3,updated=now()`, [col, id, JSON.stringify(b)]);
      else if (m === "PATCH") { const r = await pool.query(`update docs set data=data||$3,updated=now() where col=$1 and id=$2`, [col, id, JSON.stringify(b)]); if (!r.rowCount) return send(res, 404, { error: "not found" }) }
      else return send(res, 405, { error: "method" });
      return send(res, 200, { ok: true, id });
    }
    // admin: logins
    if (m === "GET" && p === "/api/users") { const { rows } = await pool.query(`select id,email,role,rep_id,pw is not null as active,invite_exp,last_login from users order by id`); return send(res, 200, rows) }
    if (m === "POST" && p === "/api/users/invite") {
      const b = await body(req), email = String(b.email || "").trim().toLowerCase(), repId = String(b.repId || "");
      if (b.role === "manager") {
        if (!/^\S+@\S+\.\S+$/.test(email)) return send(res, 400, { error: "Enter your manager's email." });
        const t = token(), ex = await pool.query(`select id,role from users where email=$1`, [email]);
        if (ex.rows[0] && ex.rows[0].role === "admin") return send(res, 400, { error: "That's your admin email." });
        if (ex.rows[0]) await pool.query(`update users set role='manager',rep_id=null,invite=$1,invite_exp=now()+interval '7 days' where id=$2`, [t, ex.rows[0].id]);
        else await pool.query(`insert into users(email,role,invite,invite_exp) values($1,'manager',$2,now()+interval '7 days')`, [email, t]);
        return send(res, 200, { link: `${BASE_URL}/invite/${t}` });
      }
      if (!/^\S+@\S+\.\S+$/.test(email)) return send(res, 400, { error: "Add a valid email to this rep first." });
      const t = token(), ex = await pool.query(`select id,role from users where email=$1 or (rep_id=$2 and role='rep')`, [email, repId]);
      if (ex.rows[0]) await pool.query(`update users set email=$1,rep_id=case when role='admin' then rep_id else $2 end,invite=$3,invite_exp=now()+interval '7 days' where id=$4`, [email, repId, t, ex.rows[0].id]);
      else await pool.query(`insert into users(email,role,rep_id,invite,invite_exp) values($1,'rep',$2,$3,now()+interval '7 days')`, [email, repId, t]);
      return send(res, 200, { link: `${BASE_URL}/invite/${t}` });
    }
    const um = p.match(/^\/api\/users\/(\d+)$/);
    if (m === "DELETE" && um) { if (+um[1] === u.id) return send(res, 400, { error: "You can't remove yourself." }); await pool.query(`delete from users where id=$1 and role<>'admin'`, [+um[1]]); return send(res, 200, { ok: true }) }
    return send(res, 404, { error: "not found" });
  } catch (e) { console.error(e); send(res, 500, { error: "Something went wrong." }) }
});

if (require.main === module) init().then(() => server.listen(PORT, () => console.log(`Quota HQ on ${PORT}`))).catch(e => { console.error(e); process.exit(1) });
module.exports = { pool, init, hydrate };
