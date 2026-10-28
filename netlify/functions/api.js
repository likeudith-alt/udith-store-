// UDITH STORE backend: one Netlify Function, data stored as JSON files in a PRIVATE GitHub repo.
// Env vars (Netlify > Site settings > Environment variables):
//   GITHUB_TOKEN    fine-grained token, Contents: read+write on the data repo only
//   GITHUB_REPO     e.g. "yourname/udith-store-data"
//   GITHUB_BRANCH   optional, default "main"
//   ADMIN_PASSWORD  your admin panel password
//   AUTH_SECRET     long random string used to sign login tokens
const crypto = require("crypto");

const { GITHUB_TOKEN, GITHUB_REPO, ADMIN_PASSWORD, AUTH_SECRET } = process.env;
const BRANCH = process.env.GITHUB_BRANCH || "main";

/* ---------- helpers ---------- */
const json = (code, body) => ({
  statusCode: code,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(body),
});
const fail = (code, msg) => json(code, { error: msg });

const b64u = (b) => Buffer.from(b).toString("base64url");
function sign(payload, ttlSec) {
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec }));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(token) {
  if (!token || !AUTH_SECRET) return null;
  const [body, sig] = String(token).split(".");
  if (!body || !sig) return null;
  const good = crypto.createHmac("sha256", AUTH_SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}
const safeEq = (x, y) => {
  const a = crypto.createHash("sha256").update(String(x)).digest();
  const b = crypto.createHash("sha256").update(String(y)).digest();
  return crypto.timingSafeEqual(a, b);
};
const hashPw = (pw, salt) =>
  new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k.toString("hex")))));

// best-effort brute-force guard (per warm instance)
const tries = new Map();
function limited(key) {
  const now = Date.now();
  const t = (tries.get(key) || []).filter((x) => now - x < 10 * 60 * 1000);
  tries.set(key, t);
  return t.length >= 8;
}
const noteFail = (key) => tries.set(key, [...(tries.get(key) || []), Date.now()]);

/* ---------- GitHub storage ---------- */
async function gh(path, opts = {}) {
  const r = await fetch("https://api.github.com" + path, {
    ...opts,
    headers: {
      Authorization: "Bearer " + GITHUB_TOKEN,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "udith-store",
      "Content-Type": "application/json",
    },
  });
  return r;
}
async function readFile(file, fallback) {
  const r = await gh(`/repos/${GITHUB_REPO}/contents/${file}?ref=${BRANCH}`);
  if (r.status === 404) return { data: fallback, sha: null };
  if (!r.ok) throw new Error("GitHub read failed: " + r.status);
  const j = await r.json();
  return { data: JSON.parse(Buffer.from(j.content, "base64").toString("utf8")), sha: j.sha };
}
async function writeFile(file, data, sha, message) {
  const r = await gh(`/repos/${GITHUB_REPO}/contents/${file}`, {
    method: "PUT",
    body: JSON.stringify({
      message,
      branch: BRANCH,
      content: Buffer.from(JSON.stringify(data, null, 1)).toString("base64"),
      ...(sha ? { sha } : {}),
    }),
  });
  if (r.status === 409 || r.status === 422) return "conflict";
  if (!r.ok) throw new Error("GitHub write failed: " + r.status);
  return "ok";
}
// read -> change -> write, retrying if two edits collide
async function mutate(file, fallback, message, fn) {
  for (let i = 0; i < 4; i++) {
    const { data, sha } = await readFile(file, fallback);
    const out = await fn(data);
    if (out && out.__abort) return out;
    if ((await writeFile(file, data, sha, message)) === "ok") {
      cache.delete(file);
      return out || {};
    }
  }
  throw new Error("Too many edits at once, try again");
}
// tiny 10s cache so many visitors don't hammer GitHub
const cache = new Map();
async function readCached(file, fallback) {
  const c = cache.get(file);
  if (c && Date.now() - c.t < 10000) return c.data;
  const { data } = await readFile(file, fallback);
  cache.set(file, { t: Date.now(), data });
  return data;
}

/* ---------- validation ---------- */
const cleanName = (n) => String(n || "").normalize("NFC").trim().replace(/\s+/g, " ");
const nameKey = (n) => cleanName(n).toLowerCase();
const validName = (n) => n.length >= 3 && n.length <= 24 && /^[\p{L}\p{N} ._-]+$/u.test(n);
const validPw = (p) => typeof p === "string" && p.length >= 6 && p.length <= 100;
const validId = (x) => /^\d{6,15}$/.test(x);
const validPrice = (p) => p === null || (Number.isFinite(p) && p >= 0 && p <= 100000000);

/* ---------- handler ---------- */
exports.handler = async (event) => {
  try {
    if (!GITHUB_TOKEN || !GITHUB_REPO || !ADMIN_PASSWORD || !AUTH_SECRET)
      return fail(500, "Server not configured (missing environment variables)");

    const i = event.path.indexOf("/api");
    const route = (i >= 0 ? event.path.slice(i + 4) : event.path).replace(/\/+$/, "") || "/";
    const method = event.httpMethod;
    let body = {};
    if (event.body) { try { body = JSON.parse(event.body); } catch { return fail(400, "Bad JSON"); } }
    const auth = (event.headers.authorization || event.headers.Authorization || "").replace(/^Bearer\s+/i, "");
    const ip = event.headers["x-nf-client-connection-ip"] || event.headers["x-forwarded-for"] || "x";
    const who = verify(auth);

    /* ----- customer accounts ----- */
    if (route === "/register" && method === "POST") {
      const name = cleanName(body.name), pw = body.password;
      if (!validName(name)) return fail(400, "Name must be 3-24 characters (letters, numbers, space . _ -)");
      if (!validPw(pw)) return fail(400, "Password must be at least 6 characters");
      if (limited("reg" + ip)) return fail(429, "Too many attempts, try later");
      noteFail("reg" + ip);
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = await hashPw(pw, salt);
      const res = await mutate("users.json", [], "new user", (users) => {
        if (users.some((u) => u.key === nameKey(name))) return { __abort: true, exists: true };
        users.push({ key: nameKey(name), name, salt, hash, created: new Date().toISOString() });
        return {};
      });
      if (res.exists) return fail(409, "That name is already taken");
      return json(200, { token: sign({ role: "user", key: nameKey(name), name }, 30 * 86400), name });
    }

    if (route === "/login" && method === "POST") {
      const key = nameKey(body.name);
      if (limited("login" + ip) || limited("login" + key)) return fail(429, "Too many attempts, try again in 10 minutes");
      const users = await readCached("users.json", []);
      const u = users.find((x) => x.key === key);
      const ok = u && safeEq(await hashPw(String(body.password || ""), u.salt), u.hash);
      if (!ok) { noteFail("login" + ip); noteFail("login" + key); return fail(401, "Wrong name or password"); }
      return json(200, { token: sign({ role: "user", key: u.key, name: u.name }, 30 * 86400), name: u.name });
    }

    if (route === "/me" && method === "GET") {
      if (!who || who.role !== "user") return fail(401, "Not logged in");
      const users = await readCached("users.json", []);
      if (!users.some((u) => u.key === who.key)) return fail(401, "Account removed");
      return json(200, { name: who.name });
    }

    /* ----- public (logged-in) ID list ----- */
    if (route === "/ids" && method === "GET") {
      if (!who) return fail(401, "Please log in");
      if (who.role === "user") {
        const users = await readCached("users.json", []);
        if (!users.some((u) => u.key === who.key)) return fail(401, "Account removed");
      }
      return json(200, { ids: await readCached("ids.json", []) });
    }

    /* ----- admin ----- */
    if (route === "/admin/login" && method === "POST") {
      if (limited("admin" + ip)) return fail(429, "Too many attempts, try again in 10 minutes");
      if (!safeEq(body.password || "", ADMIN_PASSWORD)) { noteFail("admin" + ip); return fail(401, "Wrong admin password"); }
      return json(200, { token: sign({ role: "admin" }, 12 * 3600) });
    }

    if (route.startsWith("/admin/")) {
      if (!who || who.role !== "admin") return fail(401, "Admin login required");

      if (route === "/admin/ids" && method === "GET") return json(200, { ids: (await readFile("ids.json", [])).data });
      if (route === "/admin/users" && method === "GET") {
        const users = (await readFile("users.json", [])).data;
        return json(200, { users: users.map((u) => ({ name: u.name, created: u.created })) });
      }

      // add many IDs at once (optional starting price)
      if (route === "/admin/ids/add" && method === "POST") {
        const price = body.price === "" || body.price == null ? null : Number(body.price);
        if (!validPrice(price)) return fail(400, "Bad price");
        const list = [...new Set((Array.isArray(body.ids) ? body.ids : String(body.ids || "").split(/[\s,;]+/)).map(String).filter(Boolean))];
        const bad = list.filter((x) => !validId(x));
        const good = list.filter(validId);
        let added = 0, dup = 0;
        await mutate("ids.json", [], `add ${good.length} ids`, (ids) => {
          const have = new Set(ids.map((x) => x.id));
          for (const id of good) { if (have.has(id)) dup++; else { ids.push({ id, price, sold: false }); added++; } }
        });
        return json(200, { added, duplicates: dup, invalid: bad });
      }

      // bulk / single price change.  ids: "all" or ["..."]; mode: set | add | percent | clear
      if (route === "/admin/ids/price" && method === "POST") {
        const { mode } = body, value = Number(body.value);
        if (!["set", "add", "percent", "clear"].includes(mode)) return fail(400, "Bad mode");
        if (mode !== "clear" && !Number.isFinite(value)) return fail(400, "Enter a number");
        if (mode === "set" && !validPrice(value)) return fail(400, "Bad price");
        let changed = 0, skipped = 0;
        await mutate("ids.json", [], `price ${mode} ${body.ids === "all" ? "all" : (body.ids || []).length}`, (ids) => {
          const target = body.ids === "all" ? null : new Set(body.ids || []);
          for (const x of ids) {
            if (target && !target.has(x.id)) continue;
            let p = x.price;
            if (mode === "set") p = Math.round(value);
            else if (mode === "clear") p = null;
            else if (p == null) { skipped++; continue; }
            else if (mode === "add") p = Math.max(0, Math.round(p + value));
            else p = Math.max(0, Math.round(p * (1 + value / 100)));
            x.price = p; changed++;
          }
        });
        return json(200, { changed, skipped });
      }

      if (route === "/admin/ids/sold" && method === "POST") {
        let changed = 0;
        await mutate("ids.json", [], "sold flag", (ids) => {
          const t = new Set(body.ids || []);
          for (const x of ids) if (t.has(x.id)) { x.sold = !!body.sold; changed++; }
        });
        return json(200, { changed });
      }

      if (route === "/admin/ids/delete" && method === "POST") {
        let removed = 0;
        await mutate("ids.json", [], `delete ${(body.ids || []).length} ids`, (ids) => {
          const t = new Set(body.ids || []);
          const keep = ids.filter((x) => !t.has(x.id));
          removed = ids.length - keep.length;
          ids.length = 0; ids.push(...keep);
        });
        return json(200, { removed });
      }

      if (route === "/admin/users/delete" && method === "POST") {
        const key = nameKey(body.name);
        await mutate("users.json", [], "delete user", (users) => {
          const keep = users.filter((u) => u.key !== key);
          users.length = 0; users.push(...keep);
        });
        return json(200, { ok: true });
      }

      if (route === "/admin/users/reset" && method === "POST") {
        if (!validPw(body.password)) return fail(400, "Password must be at least 6 characters");
        const key = nameKey(body.name);
        const salt = crypto.randomBytes(16).toString("hex");
        const hash = await hashPw(body.password, salt);
        const res = await mutate("users.json", [], "reset password", (users) => {
          const u = users.find((x) => x.key === key);
          if (!u) return { __abort: true };
          u.salt = salt; u.hash = hash;
        });
        return res.__abort ? fail(404, "No such user") : json(200, { ok: true });
      }
    }

    return fail(404, "Not found");
  } catch (e) {
    console.error(e);
    return fail(500, "Server error: " + e.message);
  }
};
