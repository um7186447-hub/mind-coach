import { argon2, createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COOKIE_NAME = "mc_session";
const SESSION_DAYS = 7;
const MAX_BODY_BYTES = 16 * 1024;
const ASSESSMENT_DIMENSIONS = ["stress", "anxiety", "depression", "sleep"];
const SCHEMA_DIMENSIONS = ["abandon", "rejection", "inferiority", "perfectionism", "dependence", "mistrust", "peoplepleasing", "emotionaldeprivation"];
const REFLECTION_DIMENSIONS = ["emotion_awareness", "stress_recovery", "social_support", "boundaries", "daily_rhythm", "values_direction"];
const REFLECTION_QUESTION_COUNT = 24;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_IP_LIMIT = 12;
const AUTH_IDENTITY_LIMIT = 6;
const MAX_ACTIVE_PASSWORD_KDFS = 4;
const SQLITE_CONSTRAINT_UNIQUE = 2067;
const ARGON2_OPTIONS = { parallelism: 1, tagLength: 32, memory: 19456, passes: 2 };
const DUMMY_PASSWORD_SALT = randomBytes(16);
const DATA_ENCRYPTION_PREFIX = "enc:v1:";
const argon2Async = promisify(argon2);
const scryptAsync = promisify(scrypt);

async function hashPassword(password, salt) {
  return argon2Async("argon2id", {
    ...ARGON2_OPTIONS,
    message: Buffer.from(password, "utf8"),
    nonce: salt
  });
}

function hashesMatch(candidate, stored) {
  if (!(candidate instanceof Uint8Array) || !(stored instanceof Uint8Array)) return false;
  const candidateBytes = Buffer.from(candidate);
  const storedBytes = Buffer.from(stored);
  return candidateBytes.length === storedBytes.length && timingSafeEqual(candidateBytes, storedBytes);
}

function parseDataEncryptionKey(value) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("DATA_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 random bytes).");
  }
  return Buffer.from(value, "hex");
}

function loadDataEncryptionKey(dbPath) {
  const configuredKey = process.env.DATA_ENCRYPTION_KEY;
  if (configuredKey !== undefined) return { key: parseDataEncryptionKey(configuredKey), generatedPath: null };
  if (process.env.NODE_ENV === "production") {
    throw new Error("Set DATA_ENCRYPTION_KEY to a persistent 32-byte secret in the hosting provider's secret settings.");
  }
  if (dbPath === ":memory:") return { key: randomBytes(32), generatedPath: null };

  const keyPath = `${dbPath}.key`;
  mkdirSync(dirname(keyPath), { recursive: true });
  try {
    return { key: parseDataEncryptionKey(readFileSync(keyPath, "utf8").trim()), generatedPath: null };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const key = randomBytes(32);
  try {
    writeFileSync(keyPath, key.toString("hex"), { flag: "wx", mode: 0o600 });
    return { key, generatedPath: keyPath };
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    return { key: parseDataEncryptionKey(readFileSync(keyPath, "utf8").trim()), generatedPath: null };
  }
}

function encryptStoredValue(value, key) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${DATA_ENCRYPTION_PREFIX}${nonce.toString("base64url")}:${tag.toString("base64url")}:${ciphertext.toString("base64url")}`;
}

function decryptStoredValue(value, key) {
  if (typeof value !== "string" || !value.startsWith(DATA_ENCRYPTION_PREFIX)) {
    throw new Error("Stored account data is not encrypted with the expected format.");
  }
  const [nonceText, tagText, ciphertextText, ...extra] = value.slice(DATA_ENCRYPTION_PREFIX.length).split(":");
  if (extra.length || !nonceText || !tagText || ciphertextText === undefined) {
    throw new Error("Stored account data has an invalid encrypted format.");
  }
  const nonce = Buffer.from(nonceText, "base64url");
  const tag = Buffer.from(tagText, "base64url");
  const ciphertext = Buffer.from(ciphertextText, "base64url");
  if (nonce.length !== 12 || tag.length !== 16) throw new Error("Stored account data has invalid encryption parameters.");
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function encryptJson(value, key) {
  return encryptStoredValue(JSON.stringify(value), key);
}

function decryptJson(value, key) {
  return JSON.parse(decryptStoredValue(value, key));
}

function migrateStoredResults(db, key) {
  const columns = [
    ["assessment_results", "scores_json"],
    ["schema_results", "scores_json"],
    ["reflection_results", "scores_json"],
    ["weekly_reports", "report_json"]
  ];
  const existingCiphertext = columns.map(([table, column]) =>
    db.prepare(`SELECT ${column} AS payload FROM ${table} WHERE ${column} LIKE ? LIMIT 1`).get(`${DATA_ENCRYPTION_PREFIX}%`)
  ).find(Boolean);
  if (existingCiphertext) {
    try {
      JSON.parse(decryptStoredValue(existingCiphertext.payload, key));
    } catch {
      throw new Error("Encrypted account data could not be opened. Restore the original DATA_ENCRYPTION_KEY before starting the server.");
    }
  }

  db.exec("BEGIN IMMEDIATE");
  try {
    for (const [table, column] of columns) {
      const rows = db.prepare(`SELECT id, ${column} AS payload FROM ${table} WHERE ${column} NOT LIKE ?`).all(`${DATA_ENCRYPTION_PREFIX}%`);
      const update = db.prepare(`UPDATE ${table} SET ${column} = ? WHERE id = ?`);
      for (const row of rows) {
        JSON.parse(row.payload);
        update.run(encryptStoredValue(row.payload, key), row.id);
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function weekStartUtc(value) {
  const date = new Date(value);
  date.setUTCHours(0, 0, 0, 0);
  const daysSinceMonday = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - daysSinceMonday);
  return date;
}

function createDatabase(dbPath) {
  if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_salt BLOB NOT NULL,
      password_hash BLOB NOT NULL,
      password_algorithm TEXT NOT NULL DEFAULT 'scrypt',
      data_consent_at TEXT NOT NULL,
      weekly_reports_enabled INTEGER NOT NULL CHECK (weekly_reports_enabled IN (0, 1)),
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS assessment_results (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scores_json TEXT NOT NULL,
      mode TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS assessment_user_date ON assessment_results(user_id, created_at);
    CREATE TABLE IF NOT EXISTS schema_results (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scores_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS schema_user_date ON schema_results(user_id, created_at);
    CREATE TABLE IF NOT EXISTS reflection_results (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scores_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS reflection_user_date ON reflection_results(user_id, created_at);
    CREATE TABLE IF NOT EXISTS weekly_reports (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      week_start TEXT NOT NULL,
      week_end TEXT NOT NULL,
      report_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(user_id, week_start)
    );
    CREATE INDEX IF NOT EXISTS weekly_reports_user_date ON weekly_reports(user_id, week_start DESC);
  `);
  const userColumns = db.prepare("PRAGMA table_info(users)").all();
  if (!userColumns.some(({ name }) => name === "password_algorithm")) {
    db.exec("ALTER TABLE users ADD COLUMN password_algorithm TEXT NOT NULL DEFAULT 'scrypt'");
  }
  return db;
}

function validateScoreMap(value, dimensions) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const expectedKeys = [...dimensions].sort();
  const keys = Object.keys(value).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return false;
  return dimensions.every((key) => {
    const score = value[key];
    if (typeof score === "number") return Number.isFinite(score) && score >= 0 && score <= 9;
    return score && typeof score === "object" && Number.isFinite(score.score)
      && score.score >= 0 && score.score <= 9
      && (score.max === undefined || score.max === 9);
  });
}

function normalizedScoreMap(scores, dimensions) {
  return Object.fromEntries(dimensions.map((key) => {
    const item = scores[key];
    return [key, typeof item === "number" ? item : item.score];
  }));
}

function weeklySummary(db, userId, start, end, dataEncryptionKey) {
  const previousStart = new Date(start);
  previousStart.setUTCDate(previousStart.getUTCDate() - 7);
  const assessments = db.prepare(`
    SELECT scores_json, created_at FROM assessment_results
    WHERE user_id = ? AND created_at >= ? AND created_at < ?
    ORDER BY created_at ASC
  `).all(userId, previousStart.toISOString(), end.toISOString()).map((row) => ({
    scores: decryptJson(row.scores_json, dataEncryptionKey),
    date: row.created_at
  }));
  const schemas = db.prepare(`
    SELECT scores_json, created_at FROM schema_results
    WHERE user_id = ? AND created_at >= ? AND created_at < ?
    ORDER BY created_at ASC
  `).all(userId, previousStart.toISOString(), end.toISOString()).map((row) => ({
    scores: decryptJson(row.scores_json, dataEncryptionKey),
    date: row.created_at
  }));
  const reflections = db.prepare(`
    SELECT scores_json, created_at FROM reflection_results
    WHERE user_id = ? AND created_at >= ? AND created_at < ?
    ORDER BY created_at ASC
  `).all(userId, previousStart.toISOString(), end.toISOString()).map((row) => ({
    scores: decryptJson(row.scores_json, dataEncryptionKey),
    date: row.created_at
  }));

  function comparison(rows, dimensions) {
    const previousWeek = rows.filter((row) => new Date(row.date) < start);
    const currentWeek = rows.filter((row) => new Date(row.date) >= start);
    if (!previousWeek.length || !currentWeek.length) return null;
    const previous = normalizedScoreMap(previousWeek.at(-1).scores, dimensions);
    const latest = normalizedScoreMap(currentWeek.at(-1).scores, dimensions);
    return Object.fromEntries(dimensions.map((dimension) => [dimension, {
      previousWeek: previous[dimension],
      latest: latest[dimension],
      change: latest[dimension] - previous[dimension]
    }]));
  }

  const currentAssessments = assessments.filter((row) => new Date(row.date) >= start);
  const currentSchemas = schemas.filter((row) => new Date(row.date) >= start);
  const currentReflections = reflections.filter((row) => new Date(row.date) >= start);
  return {
    assessmentCount: currentAssessments.length,
    schemaCount: currentSchemas.length,
    reflectionCount: currentReflections.length,
    assessmentChange: comparison(assessments, ASSESSMENT_DIMENSIONS),
    schemaChange: comparison(schemas, SCHEMA_DIMENSIONS),
    reflectionChange: comparison(reflections, REFLECTION_DIMENSIONS),
    note: "A reflection summary of saved scores only. Changes are not clinical progress measures and do not provide a diagnosis."
  };
}

export function createApp({
  dbPath = resolve(ROOT, ".data", "mind-coach.sqlite"),
  cookieSecure = process.env.NODE_ENV === "production",
  now = () => new Date()
} = {}) {
  const { key: dataEncryptionKey, generatedPath: generatedKeyPath } = loadDataEncryptionKey(dbPath);
  const db = createDatabase(dbPath);
  try {
    migrateStoredResults(db, dataEncryptionKey);
  } catch (error) {
    db.close();
    if (generatedKeyPath) {
      try {
        unlinkSync(generatedKeyPath);
      } catch {}
    }
    throw error;
  }
  const indexHtml = readFileSync(resolve(ROOT, "index.htm"), "utf8");
  const authAttempts = new Map();
  const configuredPublicOrigin = process.env.PUBLIC_ORIGIN ? new URL(process.env.PUBLIC_ORIGIN).origin : null;
  let activePasswordKdfs = 0;

  async function runPasswordKdf(operation) {
    if (activePasswordKdfs >= MAX_ACTIVE_PASSWORD_KDFS) {
      throw Object.assign(new Error("Authentication is temporarily busy. Please try again shortly."), {
        status: 503,
        retryAfter: 3
      });
    }
    activePasswordKdfs += 1;
    try {
      return await operation();
    } finally {
      activePasswordKdfs -= 1;
    }
  }

  function createSession(userId) {
    const token = randomBytes(32).toString("base64url");
    const createdAt = now();
    const expiresAt = new Date(createdAt.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
    db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
      .run(createHash("sha256").update(token).digest("hex"), userId, expiresAt.toISOString(), createdAt.toISOString());
    return { token, expiresAt };
  }

  function readSession(request) {
    const cookie = request.headers.cookie || "";
    const token = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE_NAME}=`))?.slice(COOKIE_NAME.length + 1);
    if (!token || token.length > 128) return null;
    const row = db.prepare(`
      SELECT sessions.token_hash, sessions.expires_at, users.id, users.email, users.weekly_reports_enabled
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(createHash("sha256").update(token).digest("hex"), now().toISOString());
    return row || null;
  }

  function setSessionCookie(response, token, expiresAt) {
    const secure = cookieSecure ? "; Secure" : "";
    response.setHeader("Set-Cookie", `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Expires=${expiresAt.toUTCString()}${secure}`);
  }

  function clearSessionCookie(response) {
    const secure = cookieSecure ? "; Secure" : "";
    response.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
  }

  function send(response, status, body, headers = {}) {
    response.writeHead(status, {
      ...securityHeaders(),
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    });
    response.end(JSON.stringify(body));
  }

  function securityHeaders() {
    const headers = {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "X-Permitted-Cross-Domain-Policies": "none"
    };
    if (process.env.NODE_ENV === "production") {
      headers["Strict-Transport-Security"] = "max-age=31536000";
    }
    return headers;
  }

  function originIsAllowed(request) {
    const origin = request.headers.origin;
    if (!origin) return false;
    let originUrl;
    try {
      originUrl = new URL(origin);
    } catch {
      return false;
    }
    const forwardedProtocol = process.env.TRUST_PROXY === "1" ? request.headers["x-forwarded-proto"]?.split(",")[0].trim() : null;
    const protocol = forwardedProtocol || (request.socket.encrypted ? "https" : "http");
    const fetchSite = request.headers["sec-fetch-site"];
    if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) return false;
    if (originUrl.protocol !== `${protocol}:`) return false;
    if (configuredPublicOrigin) return originUrl.origin === configuredPublicOrigin;
    if (process.env.NODE_ENV === "production") return false;

    const address = server.address();
    if (!address || typeof address === "string") return false;
    const allowedLoopbackHosts = address.address === "::1"
      ? new Set(["localhost", "[::1]"])
      : new Set(["localhost", "127.0.0.1"]);
    if (!allowedLoopbackHosts.has(originUrl.hostname.toLowerCase())) return false;
    return Number(originUrl.port || (protocol === "https" ? 443 : 80)) === address.port
      && originUrl.origin === `${protocol}://${request.headers.host}`;
  }

  async function readJson(request) {
    const mediaType = request.headers["content-type"]?.split(";")[0].trim().toLowerCase();
    if (mediaType !== "application/json") {
      throw Object.assign(new Error("Request must use application/json."), { status: 415 });
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) throw Object.assign(new Error("Request body is too large."), { status: 413 });
      chunks.push(chunk);
    }
    let value;
    try {
      value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw Object.assign(new Error("Request must contain valid JSON."), { status: 400 });
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw Object.assign(new Error("Request must contain a JSON object."), { status: 400 });
    }
    return value;
  }

  function consumeAuthLimit(key, limit) {
    const current = now().getTime();
    if (authAttempts.size > 10000) {
      for (const [storedKey, storedRecord] of authAttempts) {
        if (current - storedRecord.startedAt >= AUTH_WINDOW_MS) authAttempts.delete(storedKey);
      }
      while (authAttempts.size > 10000) authAttempts.delete(authAttempts.keys().next().value);
    }
    let record = authAttempts.get(key);
    if (!record || current - record.startedAt >= AUTH_WINDOW_MS) {
      record = { startedAt: current, count: 0 };
      authAttempts.set(key, record);
    }
    record.count += 1;
    return {
      allowed: record.count <= limit,
      retryAfter: Math.max(1, Math.ceil((record.startedAt + AUTH_WINDOW_MS - current) / 1000))
    };
  }

  function checkAuthRateLimit(request, email) {
    const address = request.socket.remoteAddress || "unknown";
    const key = email === undefined
      ? `ip:${address}`
      : `identity:${address}:${String(email).slice(0, 254)}`;
    return consumeAuthLimit(key, email === undefined ? AUTH_IP_LIMIT : AUTH_IDENTITY_LIMIT);
  }

  function sendRateLimit(response, result) {
    send(response, 429, { error: "Too many account requests. Please wait and try again." }, {
      "Retry-After": String(result.retryAfter)
    });
  }

  function runWeeklyReports(referenceDate = now()) {
    const latestWeekStart = weekStartUtc(referenceDate);
    latestWeekStart.setUTCDate(latestWeekStart.getUTCDate() - 7);
    const start = latestWeekStart;
    const end = new Date(start);
    end.setUTCDate(end.getUTCDate() + 7);
    const startIso = start.toISOString();
    const endIso = end.toISOString();
    const users = db.prepare("SELECT id FROM users WHERE weekly_reports_enabled = 1").all();
    const insert = db.prepare(`
      INSERT OR IGNORE INTO weekly_reports (user_id, week_start, week_end, report_json, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    db.exec("BEGIN IMMEDIATE");
    try {
      users.forEach(({ id }) => {
        const report = weeklySummary(db, id, start, end, dataEncryptionKey);
        if (!report.assessmentCount && !report.schemaCount && !report.reflectionCount) return;
        insert.run(id, startIso, endIso, encryptJson(report, dataEncryptionKey), referenceDate.toISOString());
      });
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://localhost");
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.htm")) {
      const nonce = randomBytes(18).toString("base64");
      const pageHtml = indexHtml.replace(/<script\b/gi, `<script nonce="${nonce}"`);
      const csp = [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net 'unsafe-eval'`,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "style-src-attr 'unsafe-inline'",
        "font-src 'self' data: https://fonts.gstatic.com",
        "img-src 'self' data: blob: https://images.unsplash.com",
        "connect-src 'self'",
        "media-src 'self' data: blob:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
      ];
      if (process.env.NODE_ENV === "production") csp.push("upgrade-insecure-requests");
      response.writeHead(200, {
        ...securityHeaders(),
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache",
        "Content-Security-Policy": csp.join("; ")
      });
      response.end(pageHtml);
      return;
    }

    if (!url.pathname.startsWith("/api/")) {
      send(response, 404, { error: "Not found." });
      return;
    }

    if (!["GET", "HEAD", "OPTIONS"].includes(request.method) && !originIsAllowed(request)) {
      send(response, 403, { error: "Request origin is not allowed." });
      return;
    }

    try {
      if (request.method === "POST" && ["/api/register", "/api/login"].includes(url.pathname)) {
        const ipLimit = checkAuthRateLimit(request);
        if (!ipLimit.allowed) {
          sendRateLimit(response, ipLimit);
          return;
        }
      }

      if (request.method === "POST" && url.pathname === "/api/register") {
        const body = await readJson(request);
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const password = typeof body.password === "string" ? body.password : "";
        const identityLimit = checkAuthRateLimit(request, email);
        if (!identityLimit.allowed) {
          sendRateLimit(response, identityLimit);
          return;
        }
        if (!EMAIL_PATTERN.test(email) || email.length > 254) {
          send(response, 400, { error: "Enter a valid email address." });
          return;
        }
        const passwordLength = Array.from(password).length;
        if (passwordLength < 15 || passwordLength > 128 || Buffer.byteLength(password, "utf8") > 1024) {
          send(response, 400, { error: "Use a unique password between 15 and 128 characters." });
          return;
        }
        if (body.dataConsent !== true) {
          send(response, 400, { error: "Consent is required to store assessment scores in an account." });
          return;
        }
        const salt = randomBytes(16);
        const passwordHash = await runPasswordKdf(() => hashPassword(password, salt));
        const createdAt = now().toISOString();
        let userId;
        try {
          userId = Number(db.prepare(`
            INSERT INTO users (email, password_salt, password_hash, password_algorithm, data_consent_at, weekly_reports_enabled, created_at)
            VALUES (?, ?, ?, 'argon2id', ?, ?, ?)
          `).run(email, salt, passwordHash, createdAt, body.weeklyReports === true ? 1 : 0, createdAt).lastInsertRowid);
        } catch (error) {
          if (error.errcode === SQLITE_CONSTRAINT_UNIQUE || error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
            send(response, 409, { error: "An account could not be created with those details." });
            return;
          }
          throw error;
        }
        const session = createSession(userId);
        setSessionCookie(response, session.token, session.expiresAt);
        send(response, 201, { user: { email, weeklyReports: body.weeklyReports === true } });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/login") {
        const body = await readJson(request);
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const password = typeof body.password === "string" ? body.password : "";
        const identityLimit = checkAuthRateLimit(request, email);
        if (!identityLimit.allowed) {
          sendRateLimit(response, identityLimit);
          return;
        }
        const passwordWithinLimit = Buffer.byteLength(password, "utf8") <= 1024;
        const user = db.prepare(`
          SELECT id, email, password_salt, password_hash, password_algorithm, weekly_reports_enabled
          FROM users WHERE email = ?
        `).get(email);
        let valid = false;
        if (!passwordWithinLimit) {
          await runPasswordKdf(() => hashPassword("invalid-password", DUMMY_PASSWORD_SALT));
        } else if (user?.password_algorithm === "argon2id") {
          const candidate = await runPasswordKdf(() => hashPassword(password, user.password_salt));
          valid = hashesMatch(candidate, user.password_hash);
        } else if (user?.password_algorithm === "scrypt") {
          const candidate = await runPasswordKdf(() => scryptAsync(password, user.password_salt, 64, {
            N: 2 ** 14,
            r: 8,
            p: 1,
            maxmem: 64 * 1024 * 1024
          }));
          valid = hashesMatch(candidate, user.password_hash);
        } else {
          await runPasswordKdf(() => hashPassword(password, DUMMY_PASSWORD_SALT));
        }
        if (!valid) {
          send(response, 401, { error: "Email or password is incorrect." });
          return;
        }
        if (user.password_algorithm !== "argon2id") {
          const salt = randomBytes(16);
          const passwordHash = await runPasswordKdf(() => hashPassword(password, salt));
          db.prepare("UPDATE users SET password_salt = ?, password_hash = ?, password_algorithm = 'argon2id' WHERE id = ?")
            .run(salt, passwordHash, user.id);
        }
        const session = createSession(user.id);
        setSessionCookie(response, session.token, session.expiresAt);
        send(response, 200, { user: { email: user.email, weeklyReports: Boolean(user.weekly_reports_enabled) } });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/logout") {
        const session = readSession(request);
        if (session) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(session.token_hash);
        clearSessionCookie(response);
        send(response, 200, { ok: true });
        return;
      }

      const user = readSession(request);
      if (request.method === "GET" && url.pathname === "/api/session" && !user) {
        send(response, 200, { user: null });
        return;
      }
      if (!user) {
        send(response, 401, { error: "Sign in to access account data." });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/session") {
        send(response, 200, { user: { email: user.email, weeklyReports: Boolean(user.weekly_reports_enabled) } });
        return;
      }

      if (request.method === "PATCH" && url.pathname === "/api/account/preferences") {
        const body = await readJson(request);
        if (typeof body.weeklyReports !== "boolean") {
          send(response, 400, { error: "Choose whether weekly reports should be enabled." });
          return;
        }
        db.prepare("UPDATE users SET weekly_reports_enabled = ? WHERE id = ?").run(body.weeklyReports ? 1 : 0, user.id);
        send(response, 200, { weeklyReports: body.weeklyReports });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/assessment-results") {
        const body = await readJson(request);
        if (!validateScoreMap(body.scores, ASSESSMENT_DIMENSIONS) || !["quick", "detailed", "comparative"].includes(body.mode)) {
          send(response, 400, { error: "Assessment result has an invalid format." });
          return;
        }
        const createdAt = now().toISOString();
        db.prepare("INSERT INTO assessment_results (user_id, scores_json, mode, created_at) VALUES (?, ?, ?, ?)")
          .run(user.id, encryptJson(normalizedScoreMap(body.scores, ASSESSMENT_DIMENSIONS), dataEncryptionKey), body.mode, createdAt);
        send(response, 201, { saved: true, date: createdAt });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/schema-results") {
        const body = await readJson(request);
        if (!validateScoreMap(body.scores, SCHEMA_DIMENSIONS)) {
          send(response, 400, { error: "Reflection result has an invalid format." });
          return;
        }
        const createdAt = now().toISOString();
        db.prepare("INSERT INTO schema_results (user_id, scores_json, created_at) VALUES (?, ?, ?)")
          .run(user.id, encryptJson(normalizedScoreMap(body.scores, SCHEMA_DIMENSIONS), dataEncryptionKey), createdAt);
        send(response, 201, { saved: true, date: createdAt });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/reflection-results") {
        const body = await readJson(request);
        if (!validateScoreMap(body.scores, REFLECTION_DIMENSIONS)) {
          send(response, 400, { error: "Reflection result has an invalid format." });
          return;
        }
        const createdAt = now().toISOString();
        db.prepare("INSERT INTO reflection_results (user_id, scores_json, created_at) VALUES (?, ?, ?)")
          .run(user.id, encryptJson(normalizedScoreMap(body.scores, REFLECTION_DIMENSIONS), dataEncryptionKey), createdAt);
        send(response, 201, { saved: true, date: createdAt });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/results") {
        const assessments = db.prepare(`
          SELECT scores_json, mode, created_at FROM assessment_results
          WHERE user_id = ? ORDER BY created_at DESC LIMIT 100
        `).all(user.id).map((row) => ({ scores: decryptJson(row.scores_json, dataEncryptionKey), mode: row.mode, date: row.created_at }));
        const schemas = db.prepare(`
          SELECT scores_json, created_at FROM schema_results
          WHERE user_id = ? ORDER BY created_at DESC LIMIT 100
        `).all(user.id).map((row) => ({ scores: decryptJson(row.scores_json, dataEncryptionKey), date: row.created_at }));
        const reflections = db.prepare(`
          SELECT scores_json, created_at FROM reflection_results
          WHERE user_id = ? ORDER BY created_at DESC LIMIT 100
        `).all(user.id).map((row) => ({ scores: decryptJson(row.scores_json, dataEncryptionKey), date: row.created_at }));
        send(response, 200, { assessments, schemas, reflections });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/weekly-reports") {
        if (user.weekly_reports_enabled) runWeeklyReports();
        const reports = db.prepare(`
          SELECT week_start, week_end, report_json, created_at FROM weekly_reports
          WHERE user_id = ? ORDER BY week_start DESC LIMIT 52
        `).all(user.weekly_reports_enabled ? user.id : -1).map((row) => ({
          weekStart: row.week_start,
          weekEnd: row.week_end,
          report: decryptJson(row.report_json, dataEncryptionKey),
          createdAt: row.created_at
        }));
        send(response, 200, { reports });
        return;
      }

      if (request.method === "DELETE" && url.pathname === "/api/account") {
        db.prepare("DELETE FROM users WHERE id = ?").run(user.id);
        clearSessionCookie(response);
        send(response, 200, { deleted: true });
        return;
      }

      send(response, 404, { error: "Not found." });
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 500;
      if (status >= 500) console.error("Request failed:", error);
      const headers = Number.isInteger(error.retryAfter) ? { "Retry-After": String(error.retryAfter) } : {};
      send(response, status, { error: status >= 500 ? "The request could not be completed. Please try again." : error.message }, headers);
    }
  });

  return {
    db,
    server,
    runWeeklyReports,
    listen(port = 0, host = "127.0.0.1") {
      return new Promise((resolveListen, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.removeListener("error", reject);
          resolveListen(server.address());
        });
      });
    },
    close() {
      return new Promise((resolveClose, reject) => {
        if (!server.listening) {
          db.close();
          resolveClose();
          return;
        }
        server.close((error) => {
          db.close();
          if (error) reject(error);
          else resolveClose();
        });
      });
    }
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.NODE_ENV === "production" && !process.env.PUBLIC_ORIGIN) {
    throw new Error("Set PUBLIC_ORIGIN to the HTTPS site origin before running in production.");
  }
  if (process.env.NODE_ENV === "production") {
    const publicOrigin = new URL(process.env.PUBLIC_ORIGIN);
    if (publicOrigin.protocol !== "https:" || publicOrigin.pathname !== "/" || publicOrigin.search || publicOrigin.hash) {
      throw new Error("PUBLIC_ORIGIN must be an HTTPS origin without a path, query, or fragment.");
    }
  }
  const app = createApp();
  const port = Number(process.env.PORT || 3000);
  await app.listen(port, process.env.HOST || "127.0.0.1");
  app.runWeeklyReports();
  setInterval(() => {
    try {
      app.runWeeklyReports();
    } catch (error) {
      console.error("Weekly report generation failed:", error);
    }
  }, 60 * 60 * 1000).unref();
  console.log(`Mind Coach listening on http://${process.env.HOST || "127.0.0.1"}:${port}`);
}
