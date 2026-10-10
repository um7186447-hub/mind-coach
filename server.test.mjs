import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { createApp } from "./server.mjs";

let app;
let baseUrl;
let currentTime;

beforeEach(async () => {
  currentTime = new Date("2026-10-01T12:00:00.000Z");
  app = createApp({ dbPath: ":memory:", now: () => new Date(currentTime) });
  const address = await app.listen();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await app.close();
});

async function request(path, { cookie, ...options } = {}) {
  const headers = new Headers(options.headers || {});
  if (cookie) headers.set("Cookie", cookie);
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && !headers.has("Origin")) headers.set("Origin", baseUrl);
  const response = await fetch(`${baseUrl}${path}`, { ...options, headers });
  const body = await response.json();
  return { response, body, cookie: response.headers.get("set-cookie")?.split(";")[0] };
}

async function register(email = "person@example.org", weeklyReports = true) {
  const result = await request("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password: "a-safe-test-passphrase",
      dataConsent: true,
      weeklyReports
    })
  });
  assert.equal(result.response.status, 201);
  return result.cookie;
}

const initialAssessment = {
  stress: 2,
  anxiety: 3,
  depression: 1,
  sleep: 4
};

const schemaScores = {
  abandon: 1,
  rejection: 2,
  inferiority: 3,
  perfectionism: 4,
  dependence: 5,
  mistrust: 6,
  peoplepleasing: 7,
  emotionaldeprivation: 8
};

const reflectionScores = {
  emotion_awareness: 3,
  stress_recovery: 4.5,
  social_support: 6,
  boundaries: 1.5,
  daily_rhythm: 7.5,
  values_direction: 9
};

test("serves the single-page app and keeps private APIs behind authentication", async () => {
  const page = await fetch(`${baseUrl}/?page=results`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-type"), /text\/html/);
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  assert.equal((await request("/api/results")).response.status, 401);
});

test("does not expose local AI endpoints", async () => {
  const cookie = await register("removed-ai@example.org");
  assert.equal((await request("/api/local-ai/status", { cookie })).response.status, 404);
  assert.equal((await request("/api/local-ai/analyze", { cookie, method: "POST" })).response.status, 404);
});

test("requires consent and a strong password before creating an account", async () => {
  const missingConsent = await request("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "no-consent@example.org", password: "a-safe-test-passphrase", dataConsent: false })
  });
  assert.equal(missingConsent.response.status, 400);

  const shortPassword = await request("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "short-password@example.org", password: "short", dataConsent: true })
  });
  assert.equal(shortPassword.response.status, 400);
});

test("saves only the signed-in user's results and removes them with the account", async () => {
  const cookie = await register();
  const assessment = await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: initialAssessment, mode: "quick" })
  });
  assert.equal(assessment.response.status, 201);

  const schema = await request("/api/schema-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: schemaScores })
  });
  assert.equal(schema.response.status, 201);

  const reflection = await request("/api/reflection-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: reflectionScores })
  });
  assert.equal(reflection.response.status, 201);

  const secondCookie = await register("another@example.org", false);
  const privateResults = await request("/api/results", { cookie: secondCookie });
  assert.equal(privateResults.body.assessments.length, 0);
  assert.equal(privateResults.body.schemas.length, 0);
  assert.equal(privateResults.body.reflections.length, 0);

  const ownResults = await request("/api/results", { cookie });
  assert.equal(ownResults.body.assessments.length, 1);
  assert.deepEqual(ownResults.body.assessments[0].scores, initialAssessment);
  assert.deepEqual(ownResults.body.schemas[0].scores, schemaScores);
  assert.equal(ownResults.body.reflections.length, 1);
  assert.deepEqual(ownResults.body.reflections[0].scores, reflectionScores);

  const deleted = await request("/api/account", { method: "DELETE", cookie });
  assert.equal(deleted.response.status, 200);
  assert.equal(deleted.body.deleted, true);
  assert.equal((await request("/api/results", { cookie })).response.status, 401);
  assert.equal(app.db.prepare("SELECT COUNT(*) AS count FROM assessment_results").get().count, 0);
  assert.equal(app.db.prepare("SELECT COUNT(*) AS count FROM schema_results").get().count, 0);
  assert.equal(app.db.prepare("SELECT COUNT(*) AS count FROM reflection_results").get().count, 0);
});

test("validates deeper reflection score maps", async () => {
  const cookie = await register("reflection-validation@example.org");
  const invalid = await request("/api/reflection-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: { ...reflectionScores, unexpected: 2 } })
  });
  assert.equal(invalid.response.status, 400);
  const outOfRange = await request("/api/reflection-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: { ...reflectionScores, values_direction: 10 } })
  });
  assert.equal(outOfRange.response.status, 400);
});

test("weekly reports compare latest scores across completed weeks and honor opt-in", async () => {
  const cookie = await register("weekly@example.org", true);
  await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: initialAssessment, mode: "quick" })
  });
  await request("/api/reflection-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: reflectionScores })
  });
  currentTime = new Date("2026-10-08T12:00:00.000Z");
  const thisWeekScores = { ...initialAssessment, stress: 5 };
  await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: thisWeekScores, mode: "quick" })
  });
  const thisWeekReflection = { ...reflectionScores, social_support: 3 };
  await request("/api/reflection-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: thisWeekReflection })
  });
  currentTime = new Date("2026-10-12T12:00:00.000Z");

  const reports = await request("/api/weekly-reports", { cookie });
  assert.equal(reports.response.status, 200);
  assert.equal(reports.body.reports.length, 1);
  assert.equal(reports.body.reports[0].report.assessmentCount, 1);
  assert.equal(reports.body.reports[0].report.schemaCount, 0);
  assert.equal(reports.body.reports[0].report.reflectionCount, 1);
  assert.equal(reports.body.reports[0].report.reflectionChange.social_support.previousWeek, reflectionScores.social_support);
  assert.equal(reports.body.reports[0].report.reflectionChange.social_support.latest, 3);
  assert.equal(reports.body.reports[0].report.reflectionChange.social_support.change, -3);
  assert.equal(reports.body.reports[0].report.assessmentChange.stress.previousWeek, 2);
  assert.equal(reports.body.reports[0].report.assessmentChange.stress.latest, 5);
  assert.equal(reports.body.reports[0].report.assessmentChange.stress.change, 3);
  assert.equal(reports.body.reports[0].report.schemaChange, null);

  const preference = await request("/api/account/preferences", {
    method: "PATCH",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ weeklyReports: false })
  });
  assert.equal(preference.response.status, 200);
  const optedOutReports = await request("/api/weekly-reports", { cookie });
  assert.deepEqual(optedOutReports.body.reports, []);
});

test("rejects invalid score maps and cross-origin state changes", async () => {
  const cookie = await register("validation@example.org");
  const invalidScores = await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: { ...initialAssessment, extra: 99 }, mode: "quick" })
  });
  assert.equal(invalidScores.response.status, 400);

  const rejectedOrigin = await request("/api/logout", {
    method: "POST",
    cookie,
    headers: { Origin: "https://unexpected.example" }
  });
  assert.equal(rejectedOrigin.response.status, 403);
});

test("does not generate weekly reports for accounts that did not enable them", async () => {
  const cookie = await register("no-weekly@example.org", false);
  await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: initialAssessment, mode: "quick" })
  });
  currentTime = new Date("2026-10-12T12:00:00.000Z");
  await request("/api/assessment-results", {
    method: "POST",
    cookie,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scores: initialAssessment, mode: "quick" })
  });
  const reports = await request("/api/weekly-reports", { cookie });
  assert.deepEqual(reports.body.reports, []);
  assert.equal(app.db.prepare("SELECT COUNT(*) AS count FROM weekly_reports").get().count, 0);
});
