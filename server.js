// WHOOP MCP server: lets Claude read your own WHOOP data through the official API.
// Read-only. Official WHOOP Developer API v2 only. MCP endpoint protected by an API key header.
// WHOOP tokens are stored encrypted (AES-256-GCM) on the Railway volume.

import express from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// ---------- Config ----------
const env = process.env;
const WHOOP_CLIENT_ID = env.WHOOP_CLIENT_ID;
const WHOOP_CLIENT_SECRET = env.WHOOP_CLIENT_SECRET;
const MCP_KEY = env.MCP_KEY;
const TOKEN_SECRET = env.TOKEN_SECRET;
const PUBLIC_URL =
  env.PUBLIC_URL || (env.RAILWAY_PUBLIC_DOMAIN ? `https://${env.RAILWAY_PUBLIC_DOMAIN}` : "");
const DATA_DIR = env.DATA_DIR || "/data";
const PORT = Number(env.PORT || 8080);
const DISPLAY_TZ = env.DISPLAY_TZ || "Asia/Qatar";

const required = { WHOOP_CLIENT_ID, WHOOP_CLIENT_SECRET, MCP_KEY, TOKEN_SECRET, PUBLIC_URL };
for (const [k, v] of Object.entries(required)) {
  if (!v) {
    console.error(`Missing environment variable: ${k}`);
    process.exit(1);
  }
}
if (MCP_KEY.length < 32 || TOKEN_SECRET.length < 32) {
  console.error("MCP_KEY and TOKEN_SECRET must each be at least 32 characters.");
  process.exit(1);
}

const BASE = PUBLIC_URL.replace(/\/+$/, "");
const REDIRECT_URI = `${BASE}/callback`;
const AUTH_URL = "https://api.prod.whoop.com/oauth/oauth2/auth";
const TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";
const API = "https://api.prod.whoop.com/developer";
const SCOPES =
  "offline read:recovery read:cycles read:workout read:sleep read:profile read:body_measurement";
const TOKEN_FILE = path.join(DATA_DIR, "whoop-tokens.enc");
const ENC_KEY = crypto.createHash("sha256").update(TOKEN_SECRET).digest();

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------- Encrypted token storage ----------
async function saveTokens(t) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([c.update(JSON.stringify(t), "utf8"), c.final()]);
  const tag = c.getAuthTag();
  await fs.mkdir(DATA_DIR, { recursive: true });
  const tmp = `${TOKEN_FILE}.tmp`;
  await fs.writeFile(tmp, Buffer.concat([iv, tag, enc]), { mode: 0o600 });
  await fs.rename(tmp, TOKEN_FILE);
}

async function loadTokens() {
  let buf;
  try {
    buf = await fs.readFile(TOKEN_FILE);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
  try {
    const d = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8"));
  } catch {
    throw new Error("Stored WHOOP tokens could not be decrypted (TOKEN_SECRET changed?). Re-authorise.");
  }
}

// ---------- WHOOP OAuth ----------
async function tokenRequest(params) {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: WHOOP_CLIENT_ID,
      client_secret: WHOOP_CLIENT_SECRET,
      ...params,
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.access_token) {
    throw new Error(`WHOOP token request failed (HTTP ${res.status}).`);
  }
  return {
    access_token: body.access_token,
    refresh_token: body.refresh_token,
    expires_at: Date.now() + (body.expires_in ?? 3600) * 1000,
  };
}

let tokenCache = null;
let refreshing = null;

async function getAccessToken(force = false) {
  if (!tokenCache) tokenCache = await loadTokens();
  if (!tokenCache) {
    throw new Error(
      `WHOOP is not authorised yet. Open ${BASE}/auth/start?key=YOUR_MCP_KEY in a browser and approve.`
    );
  }
  if (!force && tokenCache.expires_at - Date.now() > 120_000) return tokenCache.access_token;
  if (!tokenCache.refresh_token) {
    throw new Error("No refresh token stored. Re-authorise via /auth/start.");
  }
  if (!refreshing) {
    refreshing = (async () => {
      const t = await tokenRequest({
        grant_type: "refresh_token",
        refresh_token: tokenCache.refresh_token,
        scope: "offline",
      });
      if (!t.refresh_token) t.refresh_token = tokenCache.refresh_token;
      await saveTokens(t);
      tokenCache = t;
      return t.access_token;
    })().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

// ---------- WHOOP API (GET only) ----------
async function whoopGet(pathname, query = {}, retried = false) {
  const url = new URL(API + pathname);
  for (const [k, v] of Object.entries(query)) if (v != null) url.searchParams.set(k, String(v));
  const token = await getAccessToken(retried);
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 401 && !retried) return whoopGet(pathname, query, true);
  if (res.status === 429) throw new Error("WHOOP rate limit hit. Try again in a minute.");
  if (!res.ok) throw new Error(`WHOOP API ${pathname} returned HTTP ${res.status}.`);
  return res.json();
}

async function fetchRange(pathname, days) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 86_400_000);
  const out = [];
  let nextToken;
  for (let page = 0; page < 40; page++) {
    const body = await whoopGet(pathname, {
      start: start.toISOString(),
      end: end.toISOString(),
      limit: 25,
      nextToken,
    });
    out.push(...(body.records || []));
    nextToken = body.next_token;
    if (!nextToken) break;
  }
  return out;
}

// ---------- Formatting ----------
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);
const hrs = (ms) => (ms == null ? null : Math.round((ms / 3_600_000) * 100) / 100);
const mins = (ms) => (ms == null ? null : Math.round(ms / 60_000));
const local = (iso) =>
  iso
    ? new Date(iso).toLocaleString("en-GB", {
        timeZone: DISPLAY_TZ,
        weekday: "short",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      })
    : null;
const mean = (arr) => {
  const v = arr.filter((x) => typeof x === "number");
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
};
const byNewest = (key) => (a, b) => new Date(b[key]) - new Date(a[key]);

function fmtRecovery(r) {
  const s = r.score || {};
  return {
    date_local: local(r.created_at),
    state: r.score_state,
    recovery_pct: s.recovery_score ?? null,
    hrv_ms: r1(s.hrv_rmssd_milli),
    rhr_bpm: s.resting_heart_rate ?? null,
    spo2_pct: r1(s.spo2_percentage),
    skin_temp_c: r1(s.skin_temp_celsius),
    calibrating: s.user_calibrating ?? null,
    sleep_id: r.sleep_id,
  };
}

function fmtSleep(sl) {
  const s = sl.score || {};
  const st = s.stage_summary || {};
  const need = s.sleep_needed || {};
  const light = st.total_light_sleep_time_milli ?? 0;
  const deep = st.total_slow_wave_sleep_time_milli ?? 0;
  const rem = st.total_rem_sleep_time_milli ?? 0;
  const asleep = light + deep + rem;
  const needMs =
    (need.baseline_milli ?? 0) +
    (need.need_from_sleep_debt_milli ?? 0) +
    (need.need_from_recent_strain_milli ?? 0) +
    (need.need_from_recent_nap_milli ?? 0);
  return {
    id: sl.id,
    nap: sl.nap,
    start_local: local(sl.start),
    end_local: local(sl.end),
    state: sl.score_state,
    hours_in_bed: hrs(st.total_in_bed_time_milli),
    hours_asleep: hrs(asleep),
    deep_h: hrs(deep),
    rem_h: hrs(rem),
    light_h: hrs(light),
    awake_h: hrs(st.total_awake_time_milli),
    restorative_pct: asleep ? Math.round(((deep + rem) / asleep) * 100) : null,
    performance_pct: s.sleep_performance_percentage ?? null,
    consistency_pct: s.sleep_consistency_percentage ?? null,
    efficiency_pct: r1(s.sleep_efficiency_percentage),
    respiratory_rate: r1(s.respiratory_rate),
    disturbances: st.disturbance_count ?? null,
    sleep_needed_h: needMs ? hrs(needMs) : null,
  };
}

function fmtWorkout(w) {
  const s = w.score || {};
  const z = s.zone_durations || {};
  const zones = {
    z0: mins(z.zone_zero_milli),
    z1: mins(z.zone_one_milli),
    z2: mins(z.zone_two_milli),
    z3: mins(z.zone_three_milli),
    z4: mins(z.zone_four_milli),
    z5: mins(z.zone_five_milli),
  };
  const total = Object.values(zones).reduce((a, b) => a + (b ?? 0), 0);
  return {
    id: w.id,
    sport: w.sport_name,
    start_local: local(w.start),
    end_local: local(w.end),
    end_iso: w.end,
    duration_min: mins(new Date(w.end) - new Date(w.start)),
    state: w.score_state,
    strain: r1(s.strain),
    avg_hr: s.average_heart_rate ?? null,
    max_hr: s.max_heart_rate ?? null,
    kcal: s.kilojoule != null ? Math.round(s.kilojoule / 4.184) : null,
    percent_recorded: s.percent_recorded ?? null,
    zone_minutes: zones,
    zone0_1_share_pct: total ? Math.round((((zones.z0 ?? 0) + (zones.z1 ?? 0)) / total) * 100) : null,
  };
}

function fmtCycle(c) {
  const s = c.score || {};
  return {
    start_local: local(c.start),
    end_local: c.end ? local(c.end) : "in progress",
    state: c.score_state,
    day_strain: r1(s.strain),
    kcal: s.kilojoule != null ? Math.round(s.kilojoule / 4.184) : null,
    avg_hr: s.average_heart_rate ?? null,
    max_hr: s.max_heart_rate ?? null,
  };
}

// ---------- Tools ----------
const daysArg = { days: z.number().int().min(1).max(90).default(7).describe("How many days back (1-90)") };
const RO = { readOnlyHint: true, openWorldHint: false };

function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}
function fail(e) {
  return { isError: true, content: [{ type: "text", text: e.message || String(e) }] };
}
function tool(handler) {
  return async (args) => {
    try {
      return ok(await handler(args));
    } catch (e) {
      return fail(e);
    }
  };
}

function buildServer() {
  const server = new McpServer({ name: "whoop", version: "1.0.0" });

  server.registerTool(
    "get_readiness",
    {
      title: "Morning readiness",
      description:
        "Latest recovery and last night's sleep, compared with the previous 14 days (HRV, RHR, respiratory rate), plus day strain for today so far, yesterday and two days ago. Use before prescribing a session.",
      inputSchema: {},
      annotations: RO,
    },
    tool(async () => {
      const [recs, sleeps, cycles] = await Promise.all([
        fetchRange("/v2/recovery", 16),
        fetchRange("/v2/activity/sleep", 16),
        fetchRange("/v2/cycle", 4),
      ]);
      const scored = recs.filter((r) => r.score_state === "SCORED").sort(byNewest("created_at"));
      const latest = scored[0];
      const base = scored.slice(1, 15);
      const nights = sleeps.filter((s) => !s.nap && s.score_state === "SCORED").sort(byNewest("start"));
      const lastSleep = (latest && nights.find((s) => s.id === latest.sleep_id)) || nights[0];
      const baseNights = nights.filter((s) => s !== lastSleep).slice(0, 14);
      const bHrv = mean(base.map((r) => r.score?.hrv_rmssd_milli));
      const bRhr = mean(base.map((r) => r.score?.resting_heart_rate));
      const bResp = mean(baseNights.map((s) => s.score?.respiratory_rate));
      const cyc = cycles.sort(byNewest("start"));
      return {
        now_local: local(new Date().toISOString()),
        latest_recovery: latest ? fmtRecovery(latest) : "No scored recovery yet today",
        last_sleep: lastSleep ? fmtSleep(lastSleep) : null,
        baseline_14d: { hrv_ms: r1(bHrv), rhr_bpm: r1(bRhr), resp_rate: r1(bResp), days: base.length },
        vs_baseline: latest
          ? {
              hrv_ms: r1(latest.score.hrv_rmssd_milli - (bHrv ?? latest.score.hrv_rmssd_milli)),
              rhr_bpm: r1(latest.score.resting_heart_rate - (bRhr ?? latest.score.resting_heart_rate)),
              resp_rate:
                lastSleep?.score?.respiratory_rate != null && bResp != null
                  ? r1(lastSleep.score.respiratory_rate - bResp)
                  : null,
            }
          : null,
        day_strain: {
          today_so_far: cyc[0] ? r1(cyc[0].score?.strain) : null,
          yesterday: cyc[1] ? r1(cyc[1].score?.strain) : null,
          two_days_ago: cyc[2] ? r1(cyc[2].score?.strain) : null,
        },
      };
    })
  );

  server.registerTool(
    "get_recovery",
    {
      title: "Recovery history",
      description: "Daily recovery %, HRV, resting HR, SpO2 and skin temperature, newest first.",
      inputSchema: daysArg,
      annotations: RO,
    },
    tool(async ({ days }) => (await fetchRange("/v2/recovery", days)).sort(byNewest("created_at")).map(fmtRecovery))
  );

  server.registerTool(
    "get_sleep",
    {
      title: "Sleep history",
      description:
        "Sleep records with hours asleep, deep/REM/light, restorative %, performance, consistency, efficiency, respiratory rate and sleep need, newest first. Naps excluded unless include_naps is true.",
      inputSchema: { ...daysArg, include_naps: z.boolean().default(false) },
      annotations: RO,
    },
    tool(async ({ days, include_naps }) =>
      (await fetchRange("/v2/activity/sleep", days))
        .filter((s) => include_naps || !s.nap)
        .sort(byNewest("start"))
        .map(fmtSleep)
    )
  );

  server.registerTool(
    "get_workouts",
    {
      title: "Workout history",
      description:
        "Workouts with sport, start/end, duration, strain, avg/max HR, kcal and minutes per HR zone. zone0_1_share_pct is the share of the session spent in the lowest zones, useful for spotting rest drift in lifting sessions. No sets, reps or weights (not in the official API).",
      inputSchema: daysArg,
      annotations: RO,
    },
    tool(async ({ days }) => (await fetchRange("/v2/activity/workout", days)).sort(byNewest("start")).map(fmtWorkout))
  );

  server.registerTool(
    "get_daily_strain",
    {
      title: "Daily strain",
      description: "Day strain, kcal and HR per physiological cycle (WHOOP day), newest first.",
      inputSchema: daysArg,
      annotations: RO,
    },
    tool(async ({ days }) => (await fetchRange("/v2/cycle", days)).sort(byNewest("start")).map(fmtCycle))
  );

  server.registerTool(
    "get_body_profile",
    {
      title: "Body measurements",
      description: "Height, weight and max heart rate as stored in WHOOP.",
      inputSchema: {},
      annotations: RO,
    },
    tool(async () => {
      const b = await whoopGet("/v2/user/measurement/body");
      return {
        height_cm: b.height_meter != null ? r1(b.height_meter * 100) : null,
        weight_kg: r1(b.weight_kilogram),
        max_heart_rate: b.max_heart_rate ?? null,
      };
    })
  );

  return server;
}

// ---------- HTTP ----------
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);

app.get("/health", (_req, res) => res.json({ ok: true }));

const pendingStates = new Map();

app.get("/auth/start", (req, res) => {
  if (!safeEqual(req.query.key ?? "", MCP_KEY)) return res.status(403).send("Forbidden");
  const now = Date.now();
  for (const [s, exp] of pendingStates) if (exp < now) pendingStates.delete(s);
  const state = crypto.randomBytes(16).toString("hex");
  pendingStates.set(state, now + 10 * 60_000);
  const u = new URL(AUTH_URL);
  u.search = new URLSearchParams({
    response_type: "code",
    client_id: WHOOP_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
  }).toString();
  res.redirect(u.toString());
});

app.get("/callback", async (req, res) => {
  const state = String(req.query.state ?? "");
  const exp = pendingStates.get(state);
  pendingStates.delete(state);
  if (!exp || exp < Date.now()) return res.status(400).send("Invalid or expired state. Start again from /auth/start.");
  if (req.query.error) return res.status(400).send(`WHOOP returned: ${String(req.query.error)}`);
  try {
    const t = await tokenRequest({
      grant_type: "authorization_code",
      code: String(req.query.code ?? ""),
      redirect_uri: REDIRECT_URI,
    });
    await saveTokens(t);
    tokenCache = t;
    res.send("WHOOP connected. You can close this tab.");
  } catch (e) {
    console.error("OAuth callback failed:", e.message);
    res.status(500).send("Token exchange failed. Check the client ID, secret and redirect URI.");
  }
});

app.get("/auth/status", async (req, res) => {
  if (!safeEqual(req.query.key ?? "", MCP_KEY)) return res.status(403).send("Forbidden");
  try {
    await getAccessToken();
    res.json({ authorised: true });
  } catch (e) {
    res.json({ authorised: false, reason: e.message });
  }
});

// MCP endpoint. The key can arrive two ways:
//   1. Header (recommended): "X-API-Key: <key>" or "Authorization: Bearer <key>" on POST /mcp
//   2. In the path (older setups): POST /mcp/<key>
function headerKey(req) {
  const x = req.get("x-api-key");
  if (x) return x.trim();
  const auth = req.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

async function handleMcp(req, res) {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  res.on("close", () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("MCP request failed:", e.message);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  }
}

function methodNotAllowed(_req, res) {
  res.status(405).set("Allow", "POST").json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Method not allowed" },
    id: null,
  });
}

app.post("/mcp", express.json({ limit: "1mb" }), (req, res) => {
  if (!safeEqual(headerKey(req), MCP_KEY)) return res.status(401).json({ error: "Missing or wrong API key" });
  return handleMcp(req, res);
});
app.all("/mcp", (req, res) => {
  if (!safeEqual(headerKey(req), MCP_KEY)) return res.status(401).json({ error: "Missing or wrong API key" });
  return methodNotAllowed(req, res);
});

app.post("/mcp/:key", express.json({ limit: "1mb" }), (req, res) => {
  if (!safeEqual(req.params.key, MCP_KEY)) return res.status(404).end();
  return handleMcp(req, res);
});
app.all("/mcp/:key", (req, res) => {
  if (!safeEqual(req.params.key, MCP_KEY)) return res.status(404).end();
  return methodNotAllowed(req, res);
});

app.use((_req, res) => res.status(404).end());

app.listen(PORT, "0.0.0.0", () => {
  console.log(`WHOOP MCP server listening on ${PORT}. Redirect URI: ${REDIRECT_URI}`);
});
