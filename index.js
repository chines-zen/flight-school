require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);

const PORT = process.env.PORT || 8080;
const ADMIN_EMAIL = "chines@zendesk.com";
const REQUIRED_DB_ENV = ["DB_USER", "DB_PASSWORD", "DB_HOST", "DB_NAME", "DB_PORT"];
const APP_SECRET = process.env.APP_SECRET || "local-development-secret-change-before-production";
const AIRTABLE_META_BASE_URL = "https://api.airtable.com/v0/meta";
const AIRTABLE_DATA_BASE_URL = "https://api.airtable.com/v0";

const LLM_PROVIDER = (process.env.LLM_PROVIDER || "gemini").toLowerCase();

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.0-flash";
const GEMINI_API_BASE = process.env.GEMINI_BASE_URL || "https://generativelanguage.googleapis.com/v1beta";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const OPENAI_BASE_URL = (process.env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || "claude-3-5-sonnet-latest";
const ANTHROPIC_BASE_URL = (process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com/v1").replace(/\/$/, "");
const ANTHROPIC_VERSION = process.env.ANTHROPIC_VERSION || "2023-06-01";

const BEDROCK_BASE_URL = (process.env.AWS_ENDPOINT_URL_BEDROCK_RUNTIME || process.env.BEDROCK_BASE_URL || "").replace(/\/$/, "");
const BEDROCK_BEARER_TOKEN = process.env.AWS_BEARER_TOKEN_BEDROCK || process.env.BEDROCK_API_KEY || "";
const BEDROCK_MODEL = process.env.BEDROCK_MODEL || "us.anthropic.claude-sonnet-4-6";
const BEDROCK_ANTHROPIC_VERSION = process.env.BEDROCK_ANTHROPIC_VERSION || "bedrock-2023-05-31";

const LLM_MAX_TOKENS = Number(process.env.LLM_MAX_TOKENS || 8192);

const KB_MAX_ARTICLES_SCANNED = Number(process.env.KB_MAX_ARTICLES_SCANNED || 300);
const KB_MAX_ARTICLES_ANALYZED = Number(process.env.KB_MAX_ARTICLES_ANALYZED || 12);
const KB_ARTICLE_EXCERPT_CHARS = 2200;

const DEFAULT_SCHEMAS = {
  cx: {
    label: "CX",
    tableName: "CX Sample",
    fields: [
      { name: "OrderID", type: "singleLineText", sample: "ORD-1001" },
      { name: "OrderDate", type: "date", sample: "2026-01-15" },
      { name: "OrderDescription", type: "singleLineText", sample: "Premium support renewal" },
      { name: "Price", type: "singleLineText", sample: "199.00" },
      { name: "Quantity", type: "singleLineText", sample: "2" },
      { name: "TrackingNumber", type: "singleLineText", sample: "1Z999AA10123456784" },
      { name: "ShippingStatus", type: "singleLineText", sample: "Shipped" }
    ]
  },
  it: {
    label: "IT",
    tableName: "IT Sample",
    fields: [
      { name: "EmployeeID", type: "singleLineText", sample: "E-1001" },
      { name: "FullName", type: "singleLineText", sample: "Jane Doe" },
      { name: "Address", type: "singleLineText", sample: "101 Market St" },
      { name: "PhoneNumber", type: "singleLineText", sample: "555-0101" },
      { name: "Email", type: "singleLineText", sample: "jane.doe@example.com" },
      { name: "JobTitleRole", type: "singleLineText", sample: "Support Engineer" },
      { name: "Manager", type: "singleLineText", sample: "Sam Manager" },
      { name: "EmploymentStatus", type: "singleLineText", sample: "Active" },
      { name: "WorkWorkerType", type: "singleLineText", sample: "Hybrid" },
      { name: "HireDate", type: "date", sample: "2025-05-01" }
    ]
  }
};

function assertEnvironment() {
  const missing = REQUIRED_DB_ENV.filter((key) => !process.env[key]);
  if (missing.length) {
    throw new Error(`Missing required database environment variables: ${missing.join(", ")}`);
  }

  if (process.env.NODE_ENV === "production" && APP_SECRET.length < 32) {
    throw new Error("APP_SECRET must be at least 32 characters in production.");
  }
}

assertEnvironment();

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  max: 10
});

const app = express();
app.set("trust proxy", true);
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(
  session({
    store: new PgSession({
      pool,
      createTableIfMissing: true
    }),
    secret: APP_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);

function encryptionKey() {
  return crypto.createHash("sha256").update(APP_SECRET).digest();
}

function encryptSecret(value) {
  if (!value) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`;
}

function decryptSecret(payload) {
  if (!payload) return null;
  const [ivText, tagText, ciphertextText] = payload.split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(ivText, "base64"));
  decipher.setAuthTag(Buffer.from(tagText, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertextText, "base64")),
    decipher.final()
  ]);
  return plaintext.toString("utf8");
}

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      project_name TEXT NOT NULL,
      owner_email TEXT NOT NULL,
      client TEXT NOT NULL,
      start_date DATE,
      end_date DATE,
      success_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
      account_executive TEXT,
      arr_impact NUMERIC(14, 2),
      sfdc_account_link TEXT,
      sfdc_opportunity_link TEXT,
      airtable_base_id TEXT,
      airtable_base_name TEXT,
      airtable_table_id TEXT,
      airtable_table_name TEXT,
      airtable_key_column TEXT,
      module2_auth_users_enabled BOOLEAN NOT NULL DEFAULT false,
      module2_bot_confirmed BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS project_authorized_users (
      id SERIAL PRIMARY KEY,
      project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'Flight Crew',
      access_enabled BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(project_id, email)
    );

    ALTER TABLE project_authorized_users
      ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Flight Crew';

    ALTER TABLE project_authorized_users
      ADD COLUMN IF NOT EXISTS access_enabled BOOLEAN NOT NULL DEFAULT false;

    ALTER TABLE project_authorized_users
      ALTER COLUMN role SET DEFAULT 'Flight Crew';

    UPDATE project_authorized_users
      SET role = 'Flight Crew'
      WHERE role = 'Co-Pilot';

    CREATE TABLE IF NOT EXISTS project_airtable_config (
      project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      encrypted_pat TEXT,
      selected_columns JSONB NOT NULL DEFAULT '[]'::jsonb,
      sample_row JSONB NOT NULL DEFAULT '{}'::jsonb,
      airtable_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS project_knowledge_assessment (
      project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      source_url TEXT,
      subdomain TEXT,
      result JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_projects_owner_email ON projects (lower(owner_email));
    CREATE INDEX IF NOT EXISTS idx_authorized_users_email ON project_authorized_users (lower(email));
  `);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function displayCrewRole(role) {
  return role === "Co-Pilot" ? "Flight Crew" : (role || "Flight Crew");
}

function parsePomeriumEmail(req) {
  const raw = req.get("X-Pomerium-Claim-Email");
  if (!raw) return null;
  return normalizeEmail(raw.split(",")[0]);
}

function readIdentity(req) {
  const pomeriumEmail = parsePomeriumEmail(req);
  if (pomeriumEmail) return pomeriumEmail;

  if (process.env.NODE_ENV !== "production") {
    const devEmail = req.query.devEmail || req.get("X-Dev-Email") || req.session.devEmail || process.env.DEV_EMAIL;
    if (devEmail) {
      req.session.devEmail = normalizeEmail(devEmail);
      return req.session.devEmail;
    }
  }

  return null;
}

function requireUser(req, res, next) {
  const actualEmail = readIdentity(req);
  if (!actualEmail) {
    res.status(401).send(layout("Sign in required", `
      <section class="card narrow">
        <h1>Sign in required</h1>
        <p>This app expects Pomerium to provide <code>X-Pomerium-Claim-Email</code>.</p>
        <p>For local development, set <code>DEV_EMAIL</code> or visit <code>/?devEmail=user@zendesk.com</code>.</p>
      </section>
    `));
    return;
  }

  const actualIsAdmin = actualEmail === ADMIN_EMAIL;
  const sessionViewAsEmail = actualIsAdmin ? normalizeEmail(req.session.viewAsEmail) : "";
  const isViewingAs = Boolean(sessionViewAsEmail);
  const email = isViewingAs ? sessionViewAsEmail : actualEmail;

  req.user = {
    actualEmail,
    email,
    isAdmin: actualIsAdmin,
    isViewingAs,
    isZendesk: email.endsWith("@zendesk.com")
  };
  next();
}

function setFlash(req, message, type = "info") {
  req.session.flash = { message, type };
}

function takeFlash(req) {
  const flash = req.session.flash;
  delete req.session.flash;
  return flash;
}

function pageChrome(req, title, body) {
  const flash = takeFlash(req);
  const flashMarkup = flash ? `<div class="flash ${escapeHtml(flash.type)}">${escapeHtml(flash.message)}</div>` : "";
  const viewAsMarkup = req.user.isAdmin ? `
    <span>${escapeHtml(req.user.actualEmail)}</span>
    <span class="pill">App Admin</span>
    <button type="button" class="text-link" onclick="document.getElementById('view-as-modal').hidden = false">View As</button>
    ${req.user.isViewingAs ? `
      <span class="pill">Viewing as ${escapeHtml(req.user.email)}</span>
      <form method="post" action="/admin/view-as/exit">
        <button type="submit" class="secondary">Exit</button>
      </form>
    ` : ""}
    <div id="view-as-modal" class="modal-backdrop" hidden>
      <div class="modal">
        <div class="view-as-title">View As</div>
        <p class="hint">Enter an email to interact with the app as that user.</p>
        <form method="post" action="/admin/view-as">
          <label for="view_as_email">Email</label>
          <input id="view_as_email" name="email" type="email" value="${req.user.isViewingAs ? escapeHtml(req.user.email) : ""}" required>
          <div class="actions">
            <button type="submit">View As</button>
            <button type="button" class="secondary" onclick="document.getElementById('view-as-modal').hidden = true">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  ` : `<span>${escapeHtml(req.user.email)}</span>`;

  return layout(title, `
    <header class="topbar">
      <div class="header-left">
        <a class="brand" href="/">Zendesk Flight School</a>
      </div>
      <nav>
        ${viewAsMarkup}
      </nav>
    </header>
    <main class="container">
      ${flashMarkup}
      ${body}
    </main>
  `);
}

function layout(title, body) {
  return `<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>${escapeHtml(title)}</title>
      <style>
        :root {
          --zd-green: #03363d;
          --zd-mint: #37b8af;
          --zd-bg: #f8f9f9;
          --zd-border: #d8dcde;
          --zd-text: #2f3941;
          --zd-subtle: #68737d;
          --zd-danger: #cc3340;
          --zd-success: #038153;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          background: var(--zd-bg);
          color: var(--zd-text);
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          line-height: 1.5;
        }
        a { color: var(--zd-green); }
        code {
          background: #eef0f2;
          border-radius: 4px;
          padding: 2px 5px;
        }
        .topbar {
          align-items: center;
          background: white;
          border-bottom: 1px solid var(--zd-border);
          display: flex;
          justify-content: space-between;
          padding: 16px 32px;
        }
        .brand {
          color: var(--zd-green);
          font-size: 18px;
          font-weight: 700;
          text-decoration: none;
        }
        .header-left {
          align-items: center;
          display: flex;
          gap: 18px;
        }
        .topbar nav {
          align-items: center;
          color: var(--zd-subtle);
          display: flex;
          gap: 12px;
        }
        .topbar nav form {
          margin: 0;
        }
        .text-link {
          background: none;
          border: 0;
          color: var(--zd-green);
          font-size: 14px;
          font-weight: 400;
          padding: 0;
          text-decoration: underline;
        }
        .container {
          margin: 0 auto;
          max-width: 1180px;
          padding: 32px;
        }
        .card {
          background: white;
          border: 1px solid var(--zd-border);
          border-radius: 12px;
          box-shadow: 0 1px 2px rgba(47, 57, 65, 0.06);
          margin-bottom: 24px;
          padding: 24px;
        }
        .breadcrumb {
          color: var(--zd-subtle);
          font-size: 14px;
          font-weight: 650;
          margin-bottom: 16px;
        }
        .breadcrumb a {
          color: #1f73b7;
          text-decoration: none;
        }
        .detail-hero {
          position: relative;
        }
        .detail-hero h1 {
          font-size: 28px;
          margin-right: 110px;
        }
        .hero-title {
          align-items: center;
          display: flex;
          gap: 12px;
          margin-right: 110px;
        }
        .hero-title h1 {
          margin-right: 0;
        }
        .schedule-badge {
          border-radius: 999px;
          display: inline-block;
          font-size: 12px;
          font-weight: 800;
          padding: 5px 10px;
          text-transform: lowercase;
        }
        .schedule-badge.scheduled { background: #edf7ff; color: #1f73b7; }
        .schedule-badge.live { background: #edf8f4; color: var(--zd-success); }
        .schedule-badge.completed { background: #eef0f2; color: var(--zd-subtle); }
        .hero-title .schedule-badge {
          transform: translateY(-3px);
        }
        .status-badge {
          background: #eef0f2;
          border-radius: 999px;
          color: var(--zd-subtle);
          display: inline-block;
          font-size: 12px;
          font-weight: 700;
          padding: 5px 10px;
          text-transform: lowercase;
        }
        .status-badge.ready { background: #edf8f4; color: var(--zd-success); }
        .status-badge.active { background: #edf7ff; color: #1f73b7; }
        .status-badge.draft { background: #eef0f2; color: var(--zd-subtle); }
        .detail-hero .edit-toggle {
          position: absolute;
          right: 24px;
          top: 24px;
        }
        .edit-panel {
          border-top: 1px solid var(--zd-border);
          margin-top: 22px;
          padding-top: 18px;
        }
        .detail-list {
          margin: 0;
        }
        .detail-list dt {
          color: var(--zd-subtle);
          font-weight: 700;
          margin-bottom: 3px;
        }
        .detail-list dd {
          font-weight: 500;
          margin: 0;
        }
        .mission-layout {
          display: grid;
          gap: 24px;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        }
        .mission-control-card {
          width: 100%;
        }
        .mission-group {
          border: 1px solid var(--zd-border);
          border-radius: 10px;
          margin-bottom: 12px;
          overflow: hidden;
        }
        .mission-group summary {
          align-items: center;
          cursor: pointer;
          display: flex;
          font-weight: 750;
          justify-content: space-between;
          list-style: none;
          padding: 14px 16px;
        }
        .mission-group summary::-webkit-details-marker { display: none; }
        .mission-group[open] summary {
          background: var(--zd-green);
          color: white;
        }
        .mission-options {
          display: grid;
          gap: 10px;
          padding: 14px;
        }
        .mission-count {
          color: var(--zd-subtle);
          font-size: 12px;
          font-weight: 700;
        }
        .mission-group[open] .mission-count {
          color: white;
        }
        .mission-option {
          align-items: center;
          border: 1px solid var(--zd-border);
          border-radius: 8px;
          color: var(--zd-text);
          display: flex;
          justify-content: space-between;
          padding: 12px 14px;
        }
        .mission-option:hover {
          background: #f3f5f5;
        }
        .mission-task-title {
          align-items: center;
          display: flex;
          gap: 10px;
        }
        .mission-task-title input {
          accent-color: #1f73b7;
          width: auto;
        }
        .mission-open-link {
          color: var(--zd-green);
          font-weight: 650;
          text-decoration: none;
        }
        .mission-open-link:hover {
          text-decoration: underline;
        }
        .checklist {
          list-style: none;
          margin: 0;
          padding: 0;
        }
        .checklist li {
          align-items: center;
          border-bottom: 1px solid var(--zd-border);
          display: flex;
          gap: 10px;
          padding: 10px 0;
        }
        .check-dot {
          align-items: center;
          background: #c8ced3;
          border-radius: 50%;
          color: white;
          display: inline-flex;
          font-size: 12px;
          height: 22px;
          justify-content: center;
          width: 22px;
        }
        .check-dot.done { background: var(--zd-success); }
        .narrow { margin: 48px auto; max-width: 680px; }
        .grid { display: grid; gap: 16px; }
        .grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .kb-metrics {
          display: grid;
          gap: 12px;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          margin-bottom: 8px;
        }
        .kb-metric {
          background: #f3f5f5;
          border: 1px solid var(--zd-border);
          border-radius: 10px;
          padding: 14px 16px;
        }
        .kb-metric .num { color: var(--zd-green); font-size: 26px; font-weight: 800; line-height: 1.1; }
        .kb-metric .num small { color: var(--zd-subtle); font-size: 14px; font-weight: 700; }
        .kb-metric .lbl { color: var(--zd-subtle); font-size: 12px; font-weight: 700; margin-top: 4px; text-transform: uppercase; }
        .kb-scores { display: grid; gap: 0; }
        .kb-score-row {
          align-items: center;
          border-bottom: 1px solid var(--zd-border);
          display: flex;
          gap: 12px;
          justify-content: space-between;
          padding: 8px 0;
        }
        .kb-score-row .kb-score-label { color: var(--zd-text); font-weight: 600; }
        .kb-score-val { align-items: center; display: flex; gap: 10px; min-width: 160px; }
        .kb-bar { background: #e3e7e9; border-radius: 999px; flex: 1; height: 8px; overflow: hidden; }
        .kb-bar > span { background: var(--zd-mint); display: block; height: 100%; }
        .kb-bar.low > span { background: var(--zd-danger); }
        .kb-bar.mid > span { background: #e9a23b; }
        .kb-score-num { font-variant-numeric: tabular-nums; font-weight: 700; min-width: 34px; text-align: right; }
        .kb-tag {
          background: #e8f5f3;
          border-radius: 999px;
          color: var(--zd-green);
          display: inline-block;
          font-size: 12px;
          font-weight: 700;
          margin: 2px 4px 2px 0;
          padding: 4px 10px;
        }
        .kb-tag.retire { background: #fdecee; color: var(--zd-danger); }
        .kb-action { border-bottom: 1px solid var(--zd-border); padding: 12px 0; }
        .kb-action:last-child { border-bottom: none; }
        .kb-action .kb-action-title { font-weight: 700; }
        .kb-badge {
          border-radius: 999px;
          display: inline-block;
          font-size: 11px;
          font-weight: 800;
          margin-left: 6px;
          padding: 2px 8px;
          text-transform: uppercase;
        }
        .kb-badge.high { background: #fdecee; color: var(--zd-danger); }
        .kb-badge.med { background: #fff4e5; color: #ad5e00; }
        .kb-badge.low { background: #eef0f2; color: var(--zd-subtle); }
        .kb-exemplar { border: 1px solid var(--zd-border); border-radius: 10px; margin-bottom: 12px; padding: 14px 16px; }
        .kb-exemplar h4 { color: var(--zd-green); margin: 0 0 8px; }
        .kb-meta-line { color: var(--zd-subtle); font-size: 13px; margin-bottom: 12px; }
        .kb-running { color: var(--zd-subtle); font-weight: 650; }
        h1, h2, h3 { color: var(--zd-green); line-height: 1.2; margin: 0 0 16px; }
        p { margin: 0 0 16px; }
        label {
          color: var(--zd-text);
          display: block;
          font-weight: 650;
          margin-bottom: 6px;
        }
        input, select, textarea {
          border: 1px solid var(--zd-border);
          border-radius: 6px;
          color: var(--zd-text);
          font: inherit;
          padding: 10px 12px;
          width: 100%;
        }
        input::placeholder, textarea::placeholder {
          font-style: italic;
        }
        textarea { min-height: 100px; resize: vertical; }
        .hint { color: var(--zd-subtle); font-size: 13px; margin-top: 4px; }
        .actions {
          align-items: center;
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 18px;
        }
        button, .button {
          background: var(--zd-green);
          border: 1px solid var(--zd-green);
          border-radius: 6px;
          color: white;
          cursor: pointer;
          display: inline-block;
          font: inherit;
          font-weight: 650;
          padding: 10px 14px;
          text-decoration: none;
        }
        .button.secondary, button.secondary {
          background: white;
          color: var(--zd-green);
        }
        .button.danger, button.danger {
          background: var(--zd-danger);
          border-color: var(--zd-danger);
        }
        table {
          border-collapse: collapse;
          width: 100%;
        }
        th, td {
          border-bottom: 1px solid var(--zd-border);
          padding: 12px;
          text-align: left;
          vertical-align: top;
        }
        th { color: var(--zd-subtle); font-size: 13px; text-transform: uppercase; }
        tr.clickable { cursor: pointer; }
        tr.clickable:hover { background: #f3f5f5; }
        .toolbar {
          align-items: end;
          display: grid;
          gap: 12px;
          grid-template-columns: 1fr 220px 140px auto;
          margin-bottom: 16px;
        }
        .toolbar.live-filter {
          align-items: end;
          grid-template-columns: minmax(260px, 1fr) auto;
          max-width: 760px;
        }
        .inline-checkbox {
          align-items: center;
          color: var(--zd-subtle);
          display: flex;
          font-size: 13px;
          font-weight: 700;
          gap: 7px;
          margin-bottom: 11px;
          white-space: nowrap;
        }
        .inline-checkbox input {
          width: auto;
        }
        .sort-link {
          color: var(--zd-subtle);
          text-decoration: none;
        }
        .sort-link:hover {
          color: var(--zd-green);
          text-decoration: underline;
        }
        .pill {
          background: #e8f5f3;
          border-radius: 999px;
          color: var(--zd-green);
          display: inline-block;
          font-size: 12px;
          font-weight: 700;
          padding: 4px 9px;
        }
        .flash {
          border-radius: 8px;
          margin-bottom: 16px;
          padding: 12px 14px;
        }
        .flash.info { background: #edf7ff; border: 1px solid #b8dcff; }
        .flash.error { background: #fff0f1; border: 1px solid #ffb8c0; }
        .flash.success { background: #edf8f4; border: 1px solid #b8e4d2; }
        .steps {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-bottom: 20px;
        }
        .step {
          border: 1px solid var(--zd-border);
          border-radius: 999px;
          color: var(--zd-subtle);
          padding: 6px 10px;
        }
        .step.active {
          background: var(--zd-green);
          border-color: var(--zd-green);
          color: white;
        }
        .tabs {
          display: grid;
          gap: 16px;
          grid-template-columns: 220px minmax(0, 1fr);
        }
        .tabnav {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .tabnav a {
          border: 1px solid var(--zd-border);
          border-radius: 8px;
          padding: 10px 12px;
          text-decoration: none;
        }
        .tabnav a.active {
          background: var(--zd-green);
          border-color: var(--zd-green);
          color: white;
        }
        .copy-row {
          align-items: center;
          display: grid;
          gap: 8px;
          grid-template-columns: minmax(0, 1fr) auto;
          margin: 10px 0;
        }
        .copy-value {
          background: #f3f5f5;
          border: 1px solid var(--zd-border);
          border-radius: 6px;
          overflow-wrap: anywhere;
          padding: 10px;
        }
        .checkbox-list {
          display: grid;
          gap: 8px;
          margin-top: 10px;
        }
        .checkbox-list label {
          align-items: center;
          display: flex;
          font-weight: 500;
          gap: 8px;
          margin: 0;
        }
        .checkbox-list input { width: auto; }
        .criteria-table input[type="text"] {
          min-width: 180px;
        }
        .criteria-table col.item-col { width: 58%; }
        .criteria-table col.check-col { width: 14%; }
        .criteria-table col.action-col { width: 120px; }
        .criteria-table th {
          white-space: normal;
        }
        .criteria-table input[readonly] {
          background: transparent;
          border-color: transparent;
          padding-left: 0;
        }
        .criteria-table input[type="checkbox"] {
          accent-color: #1f73b7;
          width: auto;
        }
        .criteria-row {
          cursor: pointer;
        }
        .criteria-row:hover {
          background: #f3f5f5;
        }
        .icon-button {
          background: white;
          border-color: var(--zd-border);
          color: var(--zd-green);
          padding: 6px 9px;
        }
        .trash-button {
          background: white;
          border-color: var(--zd-border);
          color: var(--zd-danger);
          padding: 6px 9px;
        }
        .modal-backdrop {
          align-items: center;
          background: rgba(47, 57, 65, 0.45);
          display: flex;
          inset: 0;
          justify-content: center;
          padding: 24px;
          position: fixed;
          z-index: 20;
        }
        .modal-backdrop[hidden] {
          display: none;
        }
        .modal {
          background: white;
          border-radius: 12px;
          max-width: 620px;
          padding: 24px;
          width: 100%;
        }
        .view-as-title {
          color: var(--zd-text);
          font-size: 14px;
          font-weight: 400;
          margin-bottom: 8px;
        }
        .criteria-actions {
          display: flex;
          gap: 6px;
          justify-content: flex-end;
        }
        .criteria-heading {
          align-items: center;
          cursor: pointer;
          display: flex;
          gap: 8px;
          justify-content: space-between;
          list-style: none;
        }
        .criteria-heading h2 {
          margin-bottom: 0;
        }
        .criteria-heading::-webkit-details-marker {
          display: none;
        }
        .criteria-caret {
          color: var(--zd-subtle);
          font-size: 16px;
        }
        details[open] .criteria-caret {
          transform: rotate(90deg);
        }
        @media (max-width: 800px) {
          .grid.two, .grid.three, .toolbar, .tabs, .mission-layout { grid-template-columns: 1fr; }
          .topbar { align-items: flex-start; flex-direction: column; gap: 8px; padding: 16px; }
          .header-left { align-items: flex-start; flex-direction: column; gap: 6px; }
          .container { padding: 16px; }
          .detail-hero h1, .hero-title { margin-right: 0; }
          .hero-title { align-items: flex-start; flex-direction: column; gap: 6px; }
          .hero-title .schedule-badge { transform: none; }
          .detail-hero .edit-toggle { position: static; margin-bottom: 12px; }
        }
      </style>
      <script>
        function copyText(id) {
          const el = document.getElementById(id);
          if (!el) return;
          navigator.clipboard.writeText(el.innerText).then(function () {
            const button = document.querySelector('[data-copy-target="' + id + '"]');
            if (button) {
              const previous = button.innerText;
              button.innerText = "Copied";
              setTimeout(function () { button.innerText = previous; }, 1200);
            }
          });
        }
        function goTo(url) {
          window.location.href = url;
        }
      </script>
    </head>
    <body>${body}</body>
  </html>`;
}

function parseSuccessCriteria(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeSuccessCriteria(value) {
  const criteria = Array.isArray(value) ? value : [];
  const normalized = criteria.map((criterion) => {
    if (typeof criterion === "string") {
      return {
        item: criterion,
        technicalValidation: false,
        customerAgreement: false,
        notes: [""]
      };
    }

    return {
      item: String(criterion?.item || ""),
      technicalValidation: criterion?.technicalValidation === true || criterion?.technicalValidation === "true",
      customerAgreement: criterion?.customerAgreement === true || criterion?.customerAgreement === "true",
      notes: Array.isArray(criterion?.notes) && criterion.notes.length
        ? criterion.notes.map((note) => String(note || ""))
        : [""]
    };
  });

  return normalized.length ? normalized : [{
    item: "",
    technicalValidation: false,
    customerAgreement: false,
    notes: [""]
  }];
}

function parseSuccessCriteriaRows(body) {
  const items = selectedValues(body.item);

  return items.map((item, index) => {
    const notesValue = body[`notes_${index}`];
    const notes = selectedValues(notesValue).map((note) => String(note || "").trim()).filter(Boolean);
    return {
      item: String(item || "").trim(),
      technicalValidation: body[`technicalValidation_${index}`] === "true",
      customerAgreement: body[`customerAgreement_${index}`] === "true",
      notes: notes.length ? notes : [""]
    };
  }).filter((criterion) => criterion.item || criterion.technicalValidation || criterion.customerAgreement || criterion.notes.some(Boolean));
}

function parseAuthorizedUsers(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(",").map((part) => part.trim());
      if (parts.length < 2) return null;
      return { name: parts[0], email: normalizeEmail(parts[1]) };
    })
    .filter((user) => user && user.name && user.email);
}

function parseCustomFields(columnsText, samplesText) {
  const samples = {};
  String(samplesText || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const [name, ...rest] = line.split(/<>|=/);
      if (name && rest.length) samples[name.trim()] = rest.join("=").trim();
    });

  return String(columnsText || "")
    .split(/\r?\n|,/)
    .map((name) => name.trim())
    .filter(Boolean)
    .map((name) => {
      if (/\s/.test(name)) {
        throw new Error(`Column name "${name}" cannot contain spaces.`);
      }
      return {
        name,
        type: looksLikeDate(samples[name]) ? "date" : "singleLineText",
        sample: samples[name] || ""
      };
    });
}

function looksLikeDate(value) {
  if (!value) return false;
  return /^\d{4}-\d{1,2}-\d{1,2}$/.test(value) || /^\d{1,2}\/\d{1,2}\/\d{2,4}$/.test(value);
}

function fieldDefinitions(fields) {
  return fields.map((field) => {
    if (field.type === "date") {
      return {
        name: field.name,
        type: "date",
        options: {
          dateFormat: { name: "iso" }
        }
      };
    }
    return { name: field.name, type: field.type || "singleLineText" };
  });
}

function sampleRecord(fields) {
  const values = {};
  fields.forEach((field) => {
    values[field.name] = field.sample || (field.type === "date" ? "2026-01-01" : `Sample ${field.name}`);
  });
  return values;
}

function assertValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function selectedValues(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

async function airtableRequest(pat, url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${pat}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const message = data?.error?.message || data?.error || response.statusText;
    throw new Error(`Airtable ${response.status}: ${message}`);
  }
  return data;
}

async function fetchBases(pat) {
  const data = await airtableRequest(pat, `${AIRTABLE_META_BASE_URL}/bases`);
  return data.bases || [];
}

async function fetchTables(pat, baseId) {
  const data = await airtableRequest(pat, `${AIRTABLE_META_BASE_URL}/bases/${encodeURIComponent(baseId)}/tables`);
  return data.tables || [];
}

async function createAirtableTable(pat, baseId, tableName, fields) {
  return airtableRequest(pat, `${AIRTABLE_META_BASE_URL}/bases/${encodeURIComponent(baseId)}/tables`, {
    method: "POST",
    body: JSON.stringify({
      name: tableName,
      fields: fieldDefinitions(fields)
    })
  });
}

async function createAirtableSampleRecord(pat, baseId, tableIdOrName, fields) {
  return airtableRequest(pat, `${AIRTABLE_DATA_BASE_URL}/${encodeURIComponent(baseId)}/${encodeURIComponent(tableIdOrName)}`, {
    method: "POST",
    body: JSON.stringify({
      records: [{ fields: sampleRecord(fields) }]
    })
  });
}

async function fetchSampleRecords(pat, baseId, tableIdOrName) {
  const data = await airtableRequest(
    pat,
    `${AIRTABLE_DATA_BASE_URL}/${encodeURIComponent(baseId)}/${encodeURIComponent(tableIdOrName)}?maxRecords=1`
  );
  return data.records || [];
}

async function upsertAirtableConfig(projectId, values) {
  const current = await pool.query("SELECT * FROM project_airtable_config WHERE project_id = $1", [projectId]);
  const existing = current.rows[0] || {};
  await pool.query(
    `INSERT INTO project_airtable_config (
      project_id, encrypted_pat, selected_columns, sample_row, airtable_metadata, updated_at
    ) VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, now())
    ON CONFLICT (project_id) DO UPDATE SET
      encrypted_pat = COALESCE(EXCLUDED.encrypted_pat, project_airtable_config.encrypted_pat),
      selected_columns = EXCLUDED.selected_columns,
      sample_row = EXCLUDED.sample_row,
      airtable_metadata = EXCLUDED.airtable_metadata,
      updated_at = now()`,
    [
      projectId,
      values.encrypted_pat ?? existing.encrypted_pat ?? null,
      JSON.stringify(values.selected_columns ?? existing.selected_columns ?? []),
      JSON.stringify(values.sample_row ?? existing.sample_row ?? {}),
      JSON.stringify(values.airtable_metadata ?? existing.airtable_metadata ?? {})
    ]
  );
}

async function getConfig(projectId) {
  const result = await pool.query("SELECT * FROM project_airtable_config WHERE project_id = $1", [projectId]);
  return result.rows[0] || null;
}

async function getKnowledgeAssessment(projectId) {
  const result = await pool.query("SELECT * FROM project_knowledge_assessment WHERE project_id = $1", [projectId]);
  return result.rows[0] || null;
}

async function saveKnowledgeAssessment(projectId, sourceUrl, subdomain, result) {
  await pool.query(
    `INSERT INTO project_knowledge_assessment (project_id, source_url, subdomain, result, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (project_id) DO UPDATE
       SET source_url = EXCLUDED.source_url,
           subdomain = EXCLUDED.subdomain,
           result = EXCLUDED.result,
           updated_at = now()`,
    [projectId, sourceUrl, subdomain, JSON.stringify(result)]
  );
}

async function getAirtableToken(projectId) {
  const config = await getConfig(projectId);
  if (!config?.encrypted_pat) return null;
  return decryptSecret(config.encrypted_pat);
}

async function listVisibleProjects(user, options = {}) {
  const filter = `%${String(options.filter || "").toLowerCase()}%`;
  const allowedSorts = {
    project_name: "p.project_name",
    client: "p.client",
    owner_email: "p.owner_email",
    account_executive: "p.account_executive",
    start_date: "p.start_date",
    end_date: "p.end_date",
    arr_impact: "p.arr_impact",
    created_at: "p.created_at"
  };
  const sortColumn = allowedSorts[options.sort] || "p.updated_at";
  const sortDir = options.dir === "asc" ? "ASC" : "DESC";

  const hasAdminBypass = user.isAdmin && !user.isViewingAs;
  const result = hasAdminBypass
    ? await pool.query(
      `SELECT p.*
       FROM projects p
       WHERE (
         lower(p.project_name) LIKE $1 OR
         lower(p.client) LIKE $1 OR
         lower(p.owner_email) LIKE $1 OR
         lower(COALESCE(p.account_executive, '')) LIKE $1
       )
       ORDER BY ${sortColumn} ${sortDir}
       LIMIT 200`,
      [filter]
    )
    : await pool.query(
      `SELECT p.*
       FROM projects p
       WHERE (lower(p.owner_email) = lower($1) OR EXISTS (
          SELECT 1 FROM project_authorized_users pau
          WHERE pau.project_id = p.id AND lower(pau.email) = lower($1) AND pau.access_enabled = true
        ))
        AND (
          lower(p.project_name) LIKE $2 OR
          lower(p.client) LIKE $2 OR
          lower(p.owner_email) LIKE $2 OR
          lower(COALESCE(p.account_executive, '')) LIKE $2
        )
       ORDER BY ${sortColumn} ${sortDir}
       LIMIT 200`,
      [user.email, filter]
    );
  return result.rows;
}

async function getProject(projectId, user) {
  const result = await pool.query(
    `SELECT p.*,
      EXISTS (
        SELECT 1 FROM project_authorized_users pau
        WHERE pau.project_id = p.id AND lower(pau.email) = lower($2) AND pau.access_enabled = true
      ) AS is_authorized_user
     FROM projects p
     WHERE p.id = $1`,
    [projectId, user.email]
  );
  const project = result.rows[0];
  if (!project) return null;

  const hasAdminBypass = user.isAdmin && !user.isViewingAs;
  const canAccess = hasAdminBypass || normalizeEmail(project.owner_email) === user.email || project.is_authorized_user;
  return canAccess ? project : null;
}

function canManageProject(project, user) {
  return (user.isAdmin && !user.isViewingAs) || normalizeEmail(project.owner_email) === user.email;
}

function canAccessModule2(project, user) {
  if ((user.isAdmin && !user.isViewingAs) || normalizeEmail(project.owner_email) === user.email) return true;
  return project.is_authorized_user && project.module2_auth_users_enabled;
}

async function getAuthorizedUsers(projectId) {
  const result = await pool.query(
    "SELECT * FROM project_authorized_users WHERE project_id = $1 ORDER BY name",
    [projectId]
  );
  return result.rows;
}

function projectSummary(project) {
  return `
    <dl class="grid three detail-list">
      <div><dt>Client</dt><dd>${escapeHtml(project.client)}</dd></div>
      <div><dt>Owner</dt><dd>${escapeHtml(project.owner_email)}</dd></div>
      <div><dt>ARR</dt><dd>${escapeHtml(formatCurrency(project.arr_impact))}</dd></div>
      <div><dt>Start Date</dt><dd>${escapeHtml(formatDate(project.start_date))}</dd></div>
      <div><dt>End Date</dt><dd>${escapeHtml(formatDate(project.end_date))}</dd></div>
      <div><dt>Account Executive</dt><dd>${escapeHtml(project.account_executive || "")}</dd></div>
    </dl>
  `;
}

function formatDate(value) {
  return value ? String(value).slice(0, 10) : "";
}

function formatDateInput(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function formatDayMonth(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const month = date.toLocaleString("en-US", { month: "long" });
  const displayMonth = month.length > 5 ? month.slice(0, 3) : month;
  return `${displayMonth} ${date.getDate()}`;
}

function formatCurrency(value) {
  if (value === null || value === undefined || value === "") return "";
  const amount = Number(value);
  if (!Number.isFinite(amount)) return String(value);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
    minimumFractionDigits: 0
  }).format(amount);
}

function daysRemaining(value) {
  if (!value) return "";
  const end = new Date(value);
  if (Number.isNaN(end.getTime())) return "";
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  end.setHours(0, 0, 0, 0);
  const days = Math.ceil((end.getTime() - today.getTime()) / 86400000);
  if (days < 0) return "Past due";
  if (days === 0) return "Today";
  if (days === 1) return "1 day";
  return `${days} days`;
}

function formatEndDateWithRemaining(value) {
  const date = formatDate(value);
  const remaining = daysRemaining(value);
  if (!date) return "";
  return remaining ? `${date} (${remaining} remaining)` : date;
}

function flightScheduleStatus(project) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const start = project.start_date ? new Date(project.start_date) : null;
  const end = project.end_date ? new Date(project.end_date) : null;
  if (start) start.setHours(0, 0, 0, 0);
  if (end) end.setHours(0, 0, 0, 0);

  if (start && start > today) return { label: "Scheduled", className: "scheduled" };
  if (end && end < today) return { label: "Completed", className: "completed" };
  return { label: "Live", className: "live" };
}

function renderScheduleBadge(project) {
  const status = flightScheduleStatus(project);
  return `<span class="schedule-badge ${status.className}">${escapeHtml(status.label)}</span>`;
}

function formatFlightTableEndDate(project) {
  return flightScheduleStatus(project).className === "completed" ? "Completed" : formatDayMonth(project.end_date);
}

function flightStatus(project) {
  if (project.module2_bot_confirmed) return { label: "ready", className: "ready" };
  if (project.airtable_table_name || project.airtable_key_column) return { label: "active", className: "active" };
  return { label: "draft", className: "draft" };
}

function renderStatusBadge(project) {
  const status = flightStatus(project);
  return `<span class="status-badge ${status.className}">${escapeHtml(status.label)}</span>`;
}

function userRoleForFlight(project, user) {
  if (user.isAdmin) return "App Admin";
  if (normalizeEmail(project.owner_email) === user.email) return "Sales Engineer (owner)";
  if (project.is_authorized_user) return "Collaborator";
  return "Viewer";
}

function renderFlightHero(project, user) {
  return `
    <div class="breadcrumb"><a href="/">Flights</a> / ${escapeHtml(project.project_name)}</div>
    <section class="card detail-hero">
      ${canManageProject(project, user) ? '<button type="button" class="secondary edit-toggle" onclick="document.getElementById(\'flight-edit-panel\').hidden = !document.getElementById(\'flight-edit-panel\').hidden">Edit</button>' : ""}
      <div class="hero-title">
        <h1>${escapeHtml(project.project_name)}</h1>
        ${renderScheduleBadge(project)}
      </div>
      <dl class="grid three detail-list">
        <div><dt>Account</dt><dd>${escapeHtml(project.client)}</dd></div>
        <div><dt>Opp</dt><dd>${project.sfdc_opportunity_link ? `<a href="${escapeHtml(project.sfdc_opportunity_link)}" target="_blank" rel="noopener noreferrer">SFDC Link</a>` : "Not provided"}</dd></div>
        <div><dt>Account executive</dt><dd>${escapeHtml(project.account_executive || "Not provided")}</dd></div>
        <div><dt>ARR</dt><dd>${escapeHtml(formatCurrency(project.arr_impact) || "Not provided")}</dd></div>
        <div><dt>Start date</dt><dd>${escapeHtml(formatDate(project.start_date) || "Not provided")}</dd></div>
        <div><dt>End date</dt><dd>${escapeHtml(formatEndDateWithRemaining(project.end_date) || "Not provided")}</dd></div>
      </dl>
      ${canManageProject(project, user) ? renderFlightEditForm(project) : ""}
    </section>
  `;
}

function renderCopilotFlightPlaceholder(project) {
  return `
    <div class="breadcrumb"><a href="/">Flights</a> / ${escapeHtml(project.project_name)}</div>
    <section class="card">
      <h1>Flight Crew View Placeholder</h1>
      <p>This is the placeholder flight detail page for non-Zendesk Flight Crew.</p>
      <dl class="grid three detail-list">
        <div><dt>Flight</dt><dd>${escapeHtml(project.project_name)}</dd></div>
        <div><dt>Account</dt><dd>${escapeHtml(project.client)}</dd></div>
        <div><dt>End date</dt><dd>${escapeHtml(formatEndDateWithRemaining(project.end_date) || "Not provided")}</dd></div>
      </dl>
    </section>
  `;
}

function renderFlightEditForm(project) {
  return `
    <div id="flight-edit-panel" class="edit-panel" hidden>
      <h2>Edit flight details</h2>
      <form method="post" action="/projects/${project.id}/details">
        <div class="grid three">
          <div>
            <label for="edit_project_name">Flight name</label>
            <input id="edit_project_name" name="project_name" value="${escapeHtml(project.project_name)}" required>
          </div>
          <div>
            <label for="edit_client">Account</label>
            <input id="edit_client" name="client" value="${escapeHtml(project.client)}" required>
          </div>
          <div>
            <label for="edit_account_executive">Account executive</label>
            <input id="edit_account_executive" name="account_executive" value="${escapeHtml(project.account_executive || "")}">
          </div>
          <div>
            <label for="edit_arr_impact">ARR</label>
            <input id="edit_arr_impact" name="arr_impact" type="number" step="0.01" value="${escapeHtml(project.arr_impact ?? "")}">
          </div>
          <div>
            <label for="edit_start_date">Start date</label>
            <input id="edit_start_date" name="start_date" type="date" value="${escapeHtml(formatDateInput(project.start_date))}">
          </div>
          <div>
            <label for="edit_end_date">End date</label>
            <input id="edit_end_date" name="end_date" type="date" value="${escapeHtml(formatDateInput(project.end_date))}">
          </div>
          <div>
            <label for="edit_sfdc_opportunity_link">Opp SFDC link</label>
            <input id="edit_sfdc_opportunity_link" name="sfdc_opportunity_link" type="url" value="${escapeHtml(project.sfdc_opportunity_link || "")}">
          </div>
        </div>
        <div class="actions">
          <button type="submit">Save changes</button>
          <button type="button" class="secondary" onclick="document.getElementById('flight-edit-panel').hidden = true">Cancel</button>
        </div>
      </form>
    </div>
  `;
}

function renderSuccessCriteriaRow(criterion, index, canManage, editing) {
  const textReadOnly = canManage && editing ? "" : "readonly";
  const checkboxDisabled = canManage && editing ? "" : "disabled";
  return `
    <tr class="criteria-row" data-criteria-row="${index}">
      <td><input type="text" name="item" value="${escapeHtml(criterion.item)}" ${textReadOnly}></td>
      <td><input type="checkbox" name="technicalValidation_${index}" value="true" ${criterion.technicalValidation ? "checked" : ""} ${checkboxDisabled}></td>
      <td><input type="checkbox" name="customerAgreement_${index}" value="true" ${criterion.customerAgreement ? "checked" : ""} ${checkboxDisabled}></td>
      <td>
        ${canManage ? `
          <div class="criteria-actions">
          <button type="button" class="icon-button" data-edit-button ${editing ? "hidden" : ""} title="Edit" onclick="setCriteriaEditing(${index}, true)">&#9998;</button>
          <button type="button" class="icon-button" data-delete-button ${editing ? "" : "hidden"} title="Delete" onclick="deleteCriteriaRow(${index})">&#128465;</button>
          <button type="submit" class="icon-button" data-save-button ${editing ? "" : "hidden"} title="Save">&#128190;</button>
          </div>
        ` : ""}
      </td>
    </tr>
  `;
}

function renderSuccessCriteriaSection(project, canManage) {
  const criteria = normalizeSuccessCriteria(project.success_criteria);
  return `
    <details class="card" id="success-criteria-panel" open>
      <summary class="criteria-heading"><h2>Success Criteria</h2><span class="criteria-caret">&rsaquo;</span></summary>
      <form method="post" action="/projects/${project.id}/success-criteria" onsubmit="enableCriteriaFields(this)">
        <table class="criteria-table">
          <colgroup>
            <col class="item-col">
            <col class="check-col">
            <col class="check-col">
            <col class="action-col">
          </colgroup>
          <thead>
            <tr>
              <th>Item</th>
              <th>Technical Validation</th>
              <th>Customer Agreement</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="criteria-body">
            ${criteria.map((criterion, index) => renderSuccessCriteriaRow(criterion, index, canManage, false)).join("")}
          </tbody>
        </table>
        ${canManage ? '<div class="actions"><button type="button" onclick="addCriteriaRow()">Add Criteria</button></div>' : ""}
      </form>
      <script>
        function setCriteriaEditing(index, editing) {
          const row = document.querySelector('[data-criteria-row="' + index + '"]');
          row?.querySelectorAll("input").forEach((input) => {
            if (input.type === "checkbox") {
              input.disabled = !editing;
            } else {
              input.readOnly = !editing;
            }
          });
          row?.querySelector("[data-edit-button]")?.toggleAttribute("hidden", editing);
          row?.querySelector("[data-delete-button]")?.toggleAttribute("hidden", !editing);
          row?.querySelector("[data-save-button]")?.toggleAttribute("hidden", !editing);
          if (editing) {
            row?.querySelector("input")?.focus();
          }
        }
        function deleteCriteriaRow(index) {
          const row = document.querySelector('[data-criteria-row="' + index + '"]');
          const form = row?.closest("form");
          row?.querySelectorAll("input").forEach((input) => {
            if (input.type === "checkbox") input.checked = false;
            else input.value = "";
          });
          if (row) row.hidden = true;
          if (form) {
            enableCriteriaFields(form);
            form.requestSubmit();
          }
        }
        function addCriteriaRow() {
          const body = document.getElementById("criteria-body");
          const index = body.querySelectorAll("[data-criteria-row]").length;
          const row = document.createElement("tr");
          row.className = "criteria-row";
          row.dataset.criteriaRow = String(index);
          row.innerHTML = '<td><input type="text" name="item" value=""></td><td><input type="checkbox" name="technicalValidation_' + index + '" value="true"></td><td><input type="checkbox" name="customerAgreement_' + index + '" value="true"></td><td><div class="criteria-actions"><button type="button" class="icon-button" data-edit-button hidden title="Edit" onclick="setCriteriaEditing(' + index + ', true)">&#9998;</button><button type="button" class="icon-button" data-delete-button title="Delete" onclick="deleteCriteriaRow(' + index + ')">&#128465;</button><button type="submit" class="icon-button" data-save-button title="Save">&#128190;</button></div></td>';
          body.appendChild(row);
          document.getElementById("success-criteria-panel").open = true;
          row.querySelector("input").focus();
        }
        function enableCriteriaFields(form) {
          form.querySelectorAll("input").forEach((input) => {
            input.disabled = false;
            input.readOnly = false;
          });
        }
      </script>
    </details>
  `;
}

function readinessHref(project, slug) {
  return `/projects/${project.id}/readiness/${encodeURIComponent(slug)}`;
}

function airtableConfigHref(project, moduleSlug = "build-api-connection") {
  return `/projects/${project.id}/readiness/${encodeURIComponent(moduleSlug)}/airtable-config`;
}

function aiAgentConfigHref(project, moduleSlug = "build-api-connection") {
  return `/projects/${project.id}/readiness/${encodeURIComponent(moduleSlug)}/ai-agent-config`;
}

function moduleTitle(slug) {
  return READINESS_PLACEHOLDERS[slug]?.title || slug.split("-").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function renderBreadcrumb(project, items = []) {
  return `
    <div class="breadcrumb">
      <a href="/">Flights</a> / <a href="/projects/${project.id}">${escapeHtml(project.project_name)}</a>
      ${items.map((item) => ` / ${item.href ? `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a>` : escapeHtml(item.label)}`).join("")}
    </div>
  `;
}

function renderMissionControl(project) {
  const groups = [
    {
      title: "AI Readiness",
      open: true,
      options: [
        { label: "Knowledge Assessment", href: readinessHref(project, "help-center-readiness"), done: false },
        { label: "Connect Zendesk Help Center", href: readinessHref(project, "connect-zendesk-help-center"), done: false },
        { label: "Build a Simple Procedure", href: readinessHref(project, "build-simple-procedure"), done: false }
      ]
    },
    {
      title: "Advanced Bot Configuration",
      open: false,
      options: [
        { label: "Build an API Connection", href: airtableConfigHref(project), done: Boolean(project.airtable_table_name && project.airtable_key_column) },
        { label: "Connect External Content", href: readinessHref(project, "connect-external-content"), done: false },
        { label: "Build an Advanced Procedure using API calls", href: readinessHref(project, "build-advanced-procedure-api"), done: false }
      ]
    },
    {
      title: "Agent Copilot",
      open: false,
      options: [
        { label: "Task 1", href: readinessHref(project, "copilot-task-1"), done: false },
        { label: "Task 2", href: readinessHref(project, "copilot-task-2"), done: false }
      ]
    }
  ];

  return `
    <section class="card mission-control-card">
      <h2>Mission Control</h2>
      <p class="hint">Choose a configuration path. Each group expands into available options.</p>
      ${groups.map((group) => {
        const completed = group.options.filter((option) => option.done).length;
        return `
          <details class="mission-group" ${group.open ? "open" : ""}>
            <summary>
              <span>${escapeHtml(group.title)}</span>
              <span class="mission-count" data-total="${group.options.length}">${completed === group.options.length ? "🎉 " : ""}${completed}/${group.options.length} completed</span>
            </summary>
            <div class="mission-options">
              ${group.options.map((option) => `
                <div class="mission-option">
                  <span class="mission-task-title">
                    <input type="checkbox" data-mission-checkbox ${option.done ? "checked" : ""}>
                    <span>${escapeHtml(option.label)}</span>
                  </span>
                  <a class="mission-open-link" href="${escapeHtml(option.href)}">Open</a>
                </div>
              `).join("")}
            </div>
          </details>
        `;
      }).join("")}
      <script>
        document.querySelectorAll(".mission-group").forEach((group) => {
          const updateMissionCount = () => {
            const checked = group.querySelectorAll("[data-mission-checkbox]:checked").length;
            const count = group.querySelector(".mission-count");
            if (count) {
              const complete = checked === Number(count.dataset.total);
              count.textContent = (complete ? "🎉 " : "") + checked + "/" + count.dataset.total + " completed";
            }
          };
          group.querySelectorAll("[data-mission-checkbox]").forEach((checkbox) => {
            checkbox.addEventListener("change", updateMissionCount);
          });
        });
      </script>
    </section>
  `;
}

function renderChecklistItem(label, done) {
  return `<li><span class="check-dot ${done ? "done" : ""}">${done ? "&#10003;" : ""}</span><span>${escapeHtml(label)}</span></li>`;
}

const READINESS_PLACEHOLDERS = {
  "build-api-connection": { title: "Build an API Connection", description: "Configure Airtable and Zendesk AI Agent API connection." },
  "help-center-readiness": { title: "AI Readiness - Knowledge Assessment", description: "Run an AI-readiness audit of a public Zendesk Help Center." },
  "connect-zendesk-help-center": { title: "Connect Zendesk Help Center", description: "Placeholder for connecting Zendesk Help Center." },
  "build-simple-procedure": { title: "Build a Simple Procedure", description: "Placeholder for building a simple procedure." },
  "connect-external-content": { title: "Connect External Content", description: "Placeholder for connecting external content." },
  "build-advanced-procedure-api": { title: "Build an Advanced Procedure using API calls", description: "Placeholder for building an advanced procedure using API calls." },
  "copilot-task-1": { title: "Agent Copilot - Task 1", description: "Placeholder for Agent Copilot task 1." },
  "copilot-task-2": { title: "Agent Copilot - Task 2", description: "Placeholder for Agent Copilot task 2." }
};

function redirectBack(req, res) {
  const target = req.get("Referrer") || "/";
  res.redirect(target);
}

function sortHeader(label, key, currentSort, currentDir, filter, hideCompleted) {
  const isActive = currentSort === key;
  const nextDir = isActive && currentDir === "asc" ? "desc" : "asc";
  const indicator = isActive ? (currentDir === "asc" ? " ↑" : " ↓") : "";
  const params = new URLSearchParams({ sort: key, dir: nextDir });
  if (filter) params.set("filter", filter);
  if (hideCompleted) params.set("hideCompleted", "true");
  return `<a class="sort-link" href="/?${params.toString()}">${escapeHtml(label)}${indicator}</a>`;
}

app.post("/admin/view-as", requireUser, (req, res, next) => {
  try {
    if (!req.user.isAdmin) {
      res.status(403).send("Not allowed.");
      return;
    }

    const email = normalizeEmail(req.body.email);
    if (!assertValidEmail(email)) {
      throw new Error("Enter a valid email to view as.");
    }

    req.session.viewAsEmail = email;
    setFlash(req, `Viewing as ${email}.`, "success");
    redirectBack(req, res);
  } catch (error) {
    next(error);
  }
});

app.post("/admin/view-as/exit", requireUser, (req, res) => {
  if (!req.user.isAdmin) {
    res.status(403).send("Not allowed.");
    return;
  }

  delete req.session.viewAsEmail;
  setFlash(req, "Exited view-as mode.", "success");
  redirectBack(req, res);
});

app.get("/", requireUser, async (req, res, next) => {
  try {
    const sort = req.query.sort || "project_name";
    const dir = req.query.dir === "asc" ? "asc" : "desc";
    const filter = req.query.filter || "";
    const hideCompleted = req.query.hideCompleted === "true";
    const projects = (await listVisibleProjects(req.user, { sort, dir, filter }))
      .filter((project) => !hideCompleted || flightScheduleStatus(project).className !== "completed");
    const rows = projects.map((project) => `
      <tr class="clickable" onclick="goTo('/projects/${project.id}')">
        <td><strong>${escapeHtml(project.project_name)}</strong> ${renderScheduleBadge(project)}</td>
        <td>${escapeHtml(project.client)}</td>
        <td>${escapeHtml(project.owner_email)}</td>
        <td>${escapeHtml(project.account_executive || "")}</td>
        <td>${escapeHtml(formatCurrency(project.arr_impact))}</td>
        <td>${escapeHtml(formatFlightTableEndDate(project))}</td>
      </tr>
    `).join("");

    res.send(pageChrome(req, "Flights", `
      <section class="card">
        <div class="actions" style="justify-content: space-between; margin-top: 0;">
          <div>
            <h1>Flights</h1>
          </div>
          <a class="button" href="/projects/new">New flight</a>
        </div>
        <form class="toolbar live-filter" method="get" action="/" data-live-filter>
          <input type="hidden" name="sort" value="${escapeHtml(sort)}">
          <input type="hidden" name="dir" value="${escapeHtml(dir)}">
          <div>
            <input id="filter" name="filter" value="${escapeHtml(filter)}" placeholder="Filter by flight, account, SE, AE, etc." autocomplete="off">
          </div>
          <label class="inline-checkbox">
            <input type="checkbox" name="hideCompleted" value="true" ${hideCompleted ? "checked" : ""}>
            Hide completed
          </label>
        </form>
        <table>
          <thead>
            <tr>
              <th>${sortHeader("Flight", "project_name", sort, dir, filter, hideCompleted)}</th>
              <th>${sortHeader("Account", "client", sort, dir, filter, hideCompleted)}</th>
              <th>${sortHeader("SE", "owner_email", sort, dir, filter, hideCompleted)}</th>
              <th>${sortHeader("AE", "account_executive", sort, dir, filter, hideCompleted)}</th>
              <th>${sortHeader("ARR", "arr_impact", sort, dir, filter, hideCompleted)}</th>
              <th>${sortHeader("End Date", "end_date", sort, dir, filter, hideCompleted)}</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="6">No flights found.</td></tr>'}</tbody>
        </table>
        <script>
          const filterInput = document.querySelector("[data-live-filter] input[name='filter']");
          if (filterInput && sessionStorage.getItem("flightFilterShouldFocus") === "true") {
            sessionStorage.removeItem("flightFilterShouldFocus");
            filterInput.focus();
            filterInput.setSelectionRange(filterInput.value.length, filterInput.value.length);
          }
          filterInput?.addEventListener("input", function () {
            clearTimeout(window.__flightFilterTimer);
            window.__flightFilterTimer = setTimeout(() => {
              sessionStorage.setItem("flightFilterShouldFocus", "true");
              this.form.requestSubmit();
            }, 250);
          });
          document.querySelector("[data-live-filter] input[name='hideCompleted']")?.addEventListener("change", function () {
            this.form.requestSubmit();
          });
        </script>
      </section>
    `));
  } catch (error) {
    next(error);
  }
});

app.get("/projects/new", requireUser, (req, res) => {
  if (!req.user.isZendesk && !req.user.isAdmin) {
    res.status(403).send(pageChrome(req, "Zendesk user required", `
      <section class="card"><h1>Zendesk user required</h1><p>Only Zendesk users can create flights.</p></section>
    `));
    return;
  }

  res.send(pageChrome(req, "New flight", `
    <section class="card">
      <h1>New flight</h1>
      <form method="post" action="/projects">
        <div class="grid two">
          <div>
            <label for="project_name">Flight name</label>
            <input id="project_name" name="project_name" required>
          </div>
          <div>
            <label for="client">Account</label>
            <input id="client" name="client" required>
          </div>
          <div>
            <label for="account_executive">Account executive</label>
            <input id="account_executive" name="account_executive">
          </div>
          <div>
            <label for="start_date">Start date</label>
            <input id="start_date" name="start_date" type="date">
          </div>
          <div>
            <label for="end_date">End date</label>
            <input id="end_date" name="end_date" type="date">
          </div>
          <div>
            <label for="arr_impact">ARR</label>
            <input id="arr_impact" name="arr_impact" type="number" step="0.01">
          </div>
          <div>
            <label for="sfdc_opportunity_link">SFDC opportunity link</label>
            <input id="sfdc_opportunity_link" name="sfdc_opportunity_link" type="url">
          </div>
        </div>
        <div class="checkbox-list">
          <label><input type="checkbox" name="module2_auth_users_enabled" value="true"> Authorized users can access Advanced Bot Configuration</label>
        </div>
        <div class="actions">
          <button type="submit">Create flight</button>
          <a class="button secondary" href="/">Cancel</a>
        </div>
      </form>
    </section>
  `));
});

app.post("/projects", requireUser, async (req, res, next) => {
  try {
    if (!req.user.isZendesk && !req.user.isAdmin) {
      res.status(403).send("Only Zendesk users can create flights.");
      return;
    }

    const ownerEmail = req.user.email;
    if (!assertValidEmail(ownerEmail) || !ownerEmail.endsWith("@zendesk.com")) {
      throw new Error("Flight owner must be a valid Zendesk email address.");
    }

    const authorizedUsers = [];
    for (const user of authorizedUsers) {
      if (!assertValidEmail(user.email)) throw new Error(`Invalid authorized user email: ${user.email}`);
      if (user.email.endsWith("@zendesk.com")) throw new Error("Authorized users should use non-Zendesk emails.");
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `INSERT INTO projects (
          project_name, owner_email, client, start_date, end_date, success_criteria,
          account_executive, arr_impact, sfdc_account_link, sfdc_opportunity_link,
          module2_auth_users_enabled
        ) VALUES ($1, $2, $3, NULLIF($4, '')::date, NULLIF($5, '')::date, $6::jsonb, $7, NULLIF($8, '')::numeric, $9, $10, $11)
        RETURNING id`,
        [
          req.body.project_name,
          ownerEmail,
          req.body.client,
          req.body.start_date || "",
          req.body.end_date || "",
          JSON.stringify([]),
          req.body.account_executive || null,
          req.body.arr_impact || "",
          null,
          req.body.sfdc_opportunity_link || null,
          req.body.module2_auth_users_enabled === "true"
        ]
      );
      const projectId = result.rows[0].id;
      for (const user of authorizedUsers) {
        await client.query(
          "INSERT INTO project_authorized_users (project_id, name, email) VALUES ($1, $2, $3)",
          [projectId, user.name, user.email]
        );
      }
      await client.query("COMMIT");
      setFlash(req, "Flight created. Use Mission Control to pick a configuration path.", "success");
      res.redirect(`/projects/${projectId}`);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    next(error);
  }
});

app.get("/projects/:id", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }

    const authorizedUsers = await getAuthorizedUsers(project.id);
    if (!req.user.isZendesk && project.is_authorized_user) {
      res.send(pageChrome(req, `${project.project_name} Flight Crew Flight`, renderCopilotFlightPlaceholder(project)));
      return;
    }

    res.send(pageChrome(req, `${project.project_name} Flight`, `
      ${renderFlightHero(project, req.user)}
      ${renderSuccessCriteriaSection(project, canManageProject(project, req.user))}
      ${renderMissionControl(project)}
      ${renderAuthorizedUserManagement(project, authorizedUsers, canManageProject(project, req.user))}
    `));
  } catch (error) {
    next(error);
  }
});

const KNOWLEDGE_ASSESSMENT_SLUG = "help-center-readiness";

function parseZendeskSource(input) {
  const raw = String(input || "").trim();
  if (!raw) return null;
  // Bare subdomain (e.g. "acme") -> default Zendesk host.
  if (/^[a-z0-9][a-z0-9-]*$/i.test(raw)) {
    const sub = raw.toLowerCase();
    return { apiBase: `https://${sub}.zendesk.com`, label: sub };
  }
  let host;
  try {
    const url = new URL(raw.includes("://") ? raw : `https://${raw}`);
    host = url.hostname;
  } catch {
    return null;
  }
  if (!host || !host.includes(".")) return null;
  const zendeskMatch = host.match(/^([a-z0-9-]+)\.zendesk\.com$/i);
  if (zendeskMatch) {
    return { apiBase: `https://${host}`, label: zendeskMatch[1].toLowerCase() };
  }
  // Host-mapped custom domain (e.g. help.melio.com): the Help Center API is
  // served on the custom domain itself, so query it directly.
  return { apiBase: `https://${host}`, label: host.toLowerCase() };
}

async function zendeskGet(apiBase, path) {
  const url = `${apiBase}${path}`;
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!response.ok) {
    const message = data?.error?.title || data?.error || data?.description || response.statusText;
    throw new Error(`Zendesk API ${response.status}: ${message}`);
  }
  return data;
}

function nextPagePath(nextPage) {
  if (!nextPage) return null;
  try {
    const url = new URL(nextPage);
    return `${url.pathname}${url.search}`;
  } catch {
    return null;
  }
}

async function fetchHelpCenterArticles(apiBase) {
  const byId = new Map();
  let path = "/api/v2/help_center/articles.json?per_page=100";
  let pages = 0;
  while (path && byId.size < KB_MAX_ARTICLES_SCANNED && pages < 25) {
    const data = await zendeskGet(apiBase, path);
    for (const article of data.articles || []) {
      if (article.draft) continue;
      const existing = byId.get(article.id);
      const isSource = article.locale && article.source_locale && article.locale === article.source_locale;
      if (!existing || isSource) byId.set(article.id, article);
    }
    pages += 1;
    path = nextPagePath(data.next_page);
  }
  return [...byId.values()];
}

async function fetchHelpCenterTaxonomy(apiBase) {
  const sections = new Map();
  const categories = new Map();
  try {
    const data = await zendeskGet(apiBase, "/api/v2/help_center/sections.json?per_page=100");
    for (const section of data.sections || []) sections.set(section.id, { name: section.name, category_id: section.category_id });
  } catch {
    /* taxonomy is best-effort */
  }
  try {
    const data = await zendeskGet(apiBase, "/api/v2/help_center/categories.json?per_page=100");
    for (const category of data.categories || []) categories.set(category.id, category.name);
  } catch {
    /* taxonomy is best-effort */
  }
  return { sections, categories };
}

function htmlToText(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, " ")
    .trim();
}

function countWords(text) {
  return text ? text.split(/\s+/).filter(Boolean).length : 0;
}

function computeLabelHealth(articles) {
  const counts = new Map();
  let zeroLabel = 0;
  for (const article of articles) {
    const labels = article.label_names || [];
    if (!labels.length) zeroLabel += 1;
    for (const label of labels) counts.set(label, (counts.get(label) || 0) + 1);
  }
  const top = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([label, count]) => ({ label, count }));
  return {
    total: articles.length,
    zeroLabel,
    zeroLabelPct: articles.length ? Math.round((zeroLabel / articles.length) * 100) : 0,
    uniqueLabels: counts.size,
    top
  };
}

function clampScore(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(5, num));
}

function weightedCustomerService(scores) {
  return clampScore(
    clampScore(scores.clarity) * 0.2 +
      clampScore(scores.actionability) * 0.2 +
      clampScore(scores.accuracy) * 0.2 +
      clampScore(scores.troubleshooting) * 0.15 +
      clampScore(scores.empathy) * 0.1 +
      clampScore(scores.findability) * 0.1 +
      clampScore(scores.accessibility) * 0.05
  );
}

function averageScore(values) {
  const nums = values.map(clampScore);
  if (!nums.length) return 0;
  return nums.reduce((sum, n) => sum + n, 0) / nums.length;
}

function parseJsonLoose(text, providerLabel) {
  if (!text) throw new Error(`${providerLabel} returned an empty response.`);
  try {
    return JSON.parse(text);
  } catch {
    const match = text.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        /* fall through */
      }
    }
    throw new Error(`Could not parse ${providerLabel} JSON output.`);
  }
}

function llmConfigStatus() {
  if (LLM_PROVIDER === "openai") {
    return {
      provider: "openai",
      ready: Boolean(OPENAI_API_KEY),
      model: `OpenAI ${OPENAI_MODEL}`,
      envVar: "OPENAI_API_KEY",
      keyUrl: "https://platform.openai.com/api-keys"
    };
  }
  if (LLM_PROVIDER === "anthropic" || LLM_PROVIDER === "claude") {
    return {
      provider: "anthropic",
      ready: Boolean(ANTHROPIC_API_KEY),
      model: `Anthropic ${ANTHROPIC_MODEL}`,
      envVar: "ANTHROPIC_API_KEY",
      keyUrl: "https://console.anthropic.com/settings/keys"
    };
  }
  if (LLM_PROVIDER === "bedrock") {
    return {
      provider: "bedrock",
      ready: Boolean(BEDROCK_BEARER_TOKEN && BEDROCK_BASE_URL),
      model: `Bedrock ${BEDROCK_MODEL}`,
      envVar: BEDROCK_BASE_URL ? "AWS_BEARER_TOKEN_BEDROCK" : "AWS_ENDPOINT_URL_BEDROCK_RUNTIME / AWS_BEARER_TOKEN_BEDROCK",
      keyUrl: "https://ai-gateway.zende.sk"
    };
  }
  return {
    provider: "gemini",
    ready: Boolean(GEMINI_API_KEY),
    model: `Gemini ${GEMINI_MODEL}`,
    envVar: "GEMINI_API_KEY",
    keyUrl: "https://aistudio.google.com/app/apikey"
  };
}

async function geminiGenerateJSON(prompt) {
  const url = `${GEMINI_API_BASE}/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, responseMimeType: "application/json", maxOutputTokens: LLM_MAX_TOKENS }
    })
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Gemini returned an unreadable response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(`Gemini API ${response.status}: ${data?.error?.message || response.statusText}`);
  }
  const out = (data?.candidates?.[0]?.content?.parts || []).map((part) => part.text || "").join("");
  return parseJsonLoose(out, "Gemini");
}

async function openaiGenerateJSON(prompt) {
  const response = await fetch(`${OPENAI_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      temperature: 0.2,
      max_tokens: LLM_MAX_TOKENS,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: "You are an expert Zendesk Help Center content auditor. Respond with a single valid JSON object only." },
        { role: "user", content: prompt }
      ]
    })
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`OpenAI returned an unreadable response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(`OpenAI API ${response.status}: ${data?.error?.message || response.statusText}`);
  }
  const out = data?.choices?.[0]?.message?.content || "";
  return parseJsonLoose(out, "OpenAI");
}

async function anthropicGenerateJSON(prompt) {
  const response = await fetch(`${ANTHROPIC_BASE_URL}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": ANTHROPIC_VERSION
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: LLM_MAX_TOKENS,
      temperature: 0.2,
      system: "You are an expert Zendesk Help Center content auditor. Respond with a single valid JSON object only, with no markdown fences or commentary.",
      messages: [{ role: "user", content: prompt }]
    })
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Anthropic returned an unreadable response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(`Anthropic API ${response.status}: ${data?.error?.message || response.statusText}`);
  }
  const out = (data?.content || []).map((part) => part.text || "").join("");
  return parseJsonLoose(out, "Anthropic");
}

async function bedrockGenerateJSON(prompt) {
  const url = `${BEDROCK_BASE_URL}/model/${BEDROCK_MODEL}/invoke`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${BEDROCK_BEARER_TOKEN}`
    },
    body: JSON.stringify({
      anthropic_version: BEDROCK_ANTHROPIC_VERSION,
      max_tokens: LLM_MAX_TOKENS,
      temperature: 0.2,
      system: "You are an expert Zendesk Help Center content auditor. Respond with a single valid JSON object only, with no markdown fences or commentary.",
      messages: [{ role: "user", content: [{ type: "text", text: prompt }] }]
    })
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Bedrock returned an unreadable response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(`Bedrock API ${response.status}: ${data?.message || data?.error?.message || data?.error || response.statusText}`);
  }
  const out = (data?.content || []).map((part) => part.text || "").join("");
  return parseJsonLoose(out, "Bedrock");
}

async function generateAuditJSON(prompt) {
  const status = llmConfigStatus();
  if (!status.ready) {
    throw new Error(`${status.envVar} is not configured. Add it to your .env file to run the Knowledge Assessment.`);
  }
  if (status.provider === "openai") return openaiGenerateJSON(prompt);
  if (status.provider === "anthropic") return anthropicGenerateJSON(prompt);
  if (status.provider === "bedrock") return bedrockGenerateJSON(prompt);
  return geminiGenerateJSON(prompt);
}

function buildAuditPrompt(subdomain, sampled, project) {
  const articlesForPrompt = sampled.map((article) => ({
    id: article.id,
    title: article.title,
    html_url: article.html_url,
    locale: article.locale,
    labels: article.label_names || [],
    section: article.section_name || null,
    category: article.category_name || null,
    updated_at: article.updated_at,
    word_count: article.word_count,
    excerpt: article.text_excerpt
  }));
  return `You are an expert Zendesk Help Center content auditor. Audit the articles below for a customer named "${project.client || project.project_name}".

Score every article on two rubrics using a 0-5 scale where 5=Exemplary, 4=Strong, 3=Adequate, 2=Weak, 1=Poor, 0=Not present.

Customer Service quality criteria: clarity, actionability, accuracy (accuracy/completeness), troubleshooting (troubleshooting readiness), empathy (empathy & tone), findability (findability & next steps), accessibility (accessibility & inclusion).
LLM/machine readability criteria: headings (heading hierarchy), chunkability, procedures (procedure semantics), inline_semantics, terminology (terminology consistency), links_text (link/text semantics), metadata (metadata completeness), structured_data (structured data suitability), i18n (i18n readiness).

Rules:
- Do not fabricate products, plans, limits, or UI labels. If a criterion cannot be assessed, score conservatively.
- Keep all text fields concise and leadership-ready.
- "quality_snapshot" values must be the AVERAGE (one decimal) across the analyzed articles for each criterion.
- Provide up to 5 "top_actions", impact one of High/Med/Low, effort one of Low/Med/High.
- Provide up to 2 "exemplars" with before to after micro-edits. improved_title must be <= 65 characters. tldr is 3-6 short bullets.
- "per_article" must include one entry per analyzed article with its weighted CS overall and unweighted LLM overall (one decimal).

Return ONLY a JSON object with EXACTLY this shape:
{
  "quality_snapshot": {
    "customer_service": { "clarity": 0, "actionability": 0, "accuracy": 0, "troubleshooting": 0, "empathy": 0, "findability": 0, "accessibility": 0 },
    "llm_readability": { "headings": 0, "chunkability": 0, "procedures": 0, "inline_semantics": 0, "terminology": 0, "links_text": 0, "metadata": 0, "structured_data": 0, "i18n": 0 }
  },
  "systemic_gaps": ["", "", ""],
  "top_actions": [{ "action": "", "impact": "High", "effort": "Low", "why": "" }],
  "label_taxonomy": {
    "canonical": [""],
    "synonyms_to_merge": [{ "canonical": "", "synonyms": ["", ""] }],
    "retire": [""],
    "namespacing": [""]
  },
  "exemplars": [{ "article": "", "improved_title": "", "intro": "", "tldr": ["", "", ""] }],
  "per_article": [{ "id": "", "title": "", "cs_overall": 0, "llm_overall": 0 }]
}

Subdomain: ${subdomain}
Articles to analyze (JSON):
${JSON.stringify(articlesForPrompt)}`;
}

async function runKnowledgeAssessment(inputUrl, project) {
  const source = parseZendeskSource(inputUrl);
  if (!source) {
    throw new Error("Enter a valid Help Center URL (for example https://acme.zendesk.com/hc/en-us).");
  }

  const rawArticles = await fetchHelpCenterArticles(source.apiBase);
  if (!rawArticles.length) {
    throw new Error(`No public articles were found at "${source.label}". Check the URL or that the Help Center is public.`);
  }

  // Resolve the real Zendesk subdomain from an article URL (handles host-mapped custom domains).
  let subdomain = source.label;
  const sampleApiUrl = rawArticles.find((article) => article.url)?.url;
  const subdomainMatch = String(sampleApiUrl || "").match(/https?:\/\/([a-z0-9-]+)\.zendesk\.com/i);
  if (subdomainMatch) subdomain = subdomainMatch[1].toLowerCase();

  const { sections, categories } = await fetchHelpCenterTaxonomy(source.apiBase);
  for (const article of rawArticles) {
    const section = article.section_id ? sections.get(article.section_id) : null;
    article.section_name = section?.name || null;
    const categoryId = section?.category_id;
    article.category_name = categoryId ? categories.get(categoryId) || null : null;
    const text = htmlToText(article.body);
    article.word_count = countWords(text);
    article.text_excerpt = text.slice(0, KB_ARTICLE_EXCERPT_CHARS);
  }

  const labelHealth = computeLabelHealth(rawArticles);

  const sampled = [...rawArticles]
    .sort((a, b) => new Date(b.updated_at || 0) - new Date(a.updated_at || 0))
    .slice(0, KB_MAX_ARTICLES_ANALYZED);

  const prompt = buildAuditPrompt(subdomain, sampled, project);
  const analysis = await generateAuditJSON(prompt);

  const perArticleById = new Map();
  for (const row of analysis.per_article || []) {
    perArticleById.set(String(row.id), row);
  }
  const appendix = sampled.map((article) => {
    const scored = perArticleById.get(String(article.id)) || {};
    return {
      id: article.id,
      title: article.title,
      labels_count: (article.label_names || []).length,
      cs_overall: scored.cs_overall != null ? clampScore(scored.cs_overall) : null,
      llm_overall: scored.llm_overall != null ? clampScore(scored.llm_overall) : null,
      updated_at: article.updated_at,
      html_url: article.html_url
    };
  });

  const csSnapshot = analysis.quality_snapshot?.customer_service || {};
  const llmSnapshot = analysis.quality_snapshot?.llm_readability || {};
  const csOverall = weightedCustomerService(csSnapshot);
  const llmOverall = averageScore(Object.values(llmSnapshot));

  return {
    subdomain,
    runId: crypto.randomUUID(),
    runAt: new Date().toISOString(),
    model: llmConfigStatus().model,
    totalSeen: rawArticles.length,
    totalAnalyzed: sampled.length,
    labelHealth,
    csOverall,
    llmOverall,
    csSnapshot,
    llmSnapshot,
    systemicGaps: analysis.systemic_gaps || [],
    topActions: analysis.top_actions || [],
    labelTaxonomy: analysis.label_taxonomy || {},
    exemplars: analysis.exemplars || [],
    appendix
  };
}

function scoreBar(value) {
  const score = clampScore(value);
  const pct = Math.round((score / 5) * 100);
  const tone = score >= 4 ? "" : score >= 2.5 ? "mid" : "low";
  return `<div class="kb-bar ${tone}"><span style="width:${pct}%"></span></div>`;
}

function renderScoreRows(labelMap, scores) {
  return Object.entries(labelMap)
    .map(([key, label]) => {
      const value = clampScore(scores?.[key]);
      return `
        <div class="kb-score-row">
          <span class="kb-score-label">${escapeHtml(label)}</span>
          <span class="kb-score-val">
            ${scoreBar(value)}
            <span class="kb-score-num">${value.toFixed(1)}</span>
          </span>
        </div>`;
    })
    .join("");
}

function formatIsoDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return escapeHtml(String(value));
  return date.toISOString().slice(0, 10);
}

function badgeClass(level) {
  const value = String(level || "").toLowerCase();
  if (value.startsWith("h")) return "high";
  if (value.startsWith("m")) return "med";
  return "low";
}

function renderAssessmentResult(result) {
  const CS_LABELS = {
    clarity: "Clarity",
    actionability: "Actionability",
    accuracy: "Accuracy / Completeness",
    troubleshooting: "Troubleshooting",
    empathy: "Empathy & Tone",
    findability: "Findability",
    accessibility: "Accessibility"
  };
  const LLM_LABELS = {
    headings: "Heading Hierarchy",
    chunkability: "Chunkability",
    procedures: "Procedure Semantics",
    inline_semantics: "Inline Semantics",
    terminology: "Terminology",
    links_text: "Link / Text Semantics",
    metadata: "Metadata",
    structured_data: "Structured Data",
    i18n: "i18n Readiness"
  };

  const topLabels = result.labelHealth.top.length
    ? result.labelHealth.top.map((item) => `${escapeHtml(item.label)} (${item.count})`).join(", ")
    : "None found";

  const gapsMarkup = result.systemicGaps.length
    ? `<ul>${result.systemicGaps.map((gap) => `<li>${escapeHtml(gap)}</li>`).join("")}</ul>`
    : `<p class="hint">No systemic gaps reported.</p>`;

  const actionsMarkup = result.topActions.length
    ? result.topActions
        .map(
          (action) => `
          <div class="kb-action">
            <div class="kb-action-title">${escapeHtml(action.action || "")}
              <span class="kb-badge ${badgeClass(action.impact)}">Impact: ${escapeHtml(action.impact || "?")}</span>
              <span class="kb-badge low">Effort: ${escapeHtml(action.effort || "?")}</span>
            </div>
            ${action.why ? `<p class="hint">${escapeHtml(action.why)}</p>` : ""}
          </div>`
        )
        .join("")
    : `<p class="hint">No actions reported.</p>`;

  const taxonomy = result.labelTaxonomy || {};
  const canonicalMarkup = (taxonomy.canonical || []).length
    ? (taxonomy.canonical || []).map((label) => `<span class="kb-tag">${escapeHtml(label)}</span>`).join("")
    : `<span class="hint">No canonical set suggested.</span>`;
  const synonymMarkup = (taxonomy.synonyms_to_merge || []).length
    ? `<ul>${(taxonomy.synonyms_to_merge || [])
        .map((item) => `<li><strong>${escapeHtml(item.canonical || "")}</strong>: ${escapeHtml((item.synonyms || []).join(", "))}</li>`)
        .join("")}</ul>`
    : "";
  const retireMarkup = (taxonomy.retire || []).length
    ? `<p><strong>Low-signal labels to retire:</strong> ${(taxonomy.retire || [])
        .map((label) => `<span class="kb-tag retire">${escapeHtml(label)}</span>`)
        .join("")}</p>`
    : "";
  const namespaceMarkup = (taxonomy.namespacing || []).length
    ? `<p class="hint">Optional namespacing: ${(taxonomy.namespacing || []).map((ns) => escapeHtml(ns)).join(", ")}</p>`
    : "";

  const exemplarsMarkup = result.exemplars.length
    ? result.exemplars
        .map(
          (example) => `
          <div class="kb-exemplar">
            <h4>${escapeHtml(example.article || "Example")}</h4>
            ${example.improved_title ? `<p><strong>Improved title:</strong> ${escapeHtml(example.improved_title)}</p>` : ""}
            ${example.intro ? `<p><strong>One-line intro:</strong> ${escapeHtml(example.intro)}</p>` : ""}
            ${(example.tldr || []).length ? `<p><strong>TL;DR:</strong></p><ul>${(example.tldr || []).map((bullet) => `<li>${escapeHtml(bullet)}</li>`).join("")}</ul>` : ""}
          </div>`
        )
        .join("")
    : `<p class="hint">No exemplars generated.</p>`;

  const appendixRows = result.appendix
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(String(row.id))}</td>
        <td>${row.html_url ? `<a href="${escapeHtml(row.html_url)}" target="_blank" rel="noopener">${escapeHtml(row.title || "(untitled)")}</a>` : escapeHtml(row.title || "(untitled)")}</td>
        <td>${row.labels_count}</td>
        <td>${row.cs_overall != null ? row.cs_overall.toFixed(1) : "—"}</td>
        <td>${row.llm_overall != null ? row.llm_overall.toFixed(1) : "—"}</td>
        <td>${formatIsoDate(row.updated_at)}</td>
      </tr>`
    )
    .join("");

  return `
    <section class="card">
      <h2>Help Center Audit — Executive Summary</h2>
      <p class="kb-meta-line">
        Subdomain: <code>${escapeHtml(result.subdomain)}</code> &bull;
        Date: ${escapeHtml(formatIsoDate(result.runAt))} &bull;
        Run ID: <code>${escapeHtml(result.runId)}</code> &bull;
        Model: ${escapeHtml(result.model)}
      </p>
      <div class="kb-metrics">
        <div class="kb-metric"><div class="num">${result.csOverall.toFixed(1)}<small>/5</small></div><div class="lbl">Customer Service (weighted)</div></div>
        <div class="kb-metric"><div class="num">${result.llmOverall.toFixed(1)}<small>/5</small></div><div class="lbl">LLM Readability</div></div>
        <div class="kb-metric"><div class="num">${result.totalAnalyzed}<small>/${result.totalSeen}</small></div><div class="lbl">Coverage (analyzed/seen)</div></div>
        <div class="kb-metric"><div class="num">${result.labelHealth.zeroLabelPct}<small>%</small></div><div class="lbl">Articles with 0 labels</div></div>
      </div>
      <p class="hint">Quality scores are produced by ${escapeHtml(result.model)} over the ${result.totalAnalyzed} most recently updated articles. Label health and coverage are computed across all ${result.totalSeen} scanned articles.</p>
    </section>

    <div class="grid two">
      <section class="card">
        <h3>Customer Service Snapshot</h3>
        <div class="kb-scores">${renderScoreRows(CS_LABELS, result.csSnapshot)}</div>
      </section>
      <section class="card">
        <h3>LLM Readability Snapshot</h3>
        <div class="kb-scores">${renderScoreRows(LLM_LABELS, result.llmSnapshot)}</div>
      </section>
    </div>

    <div class="grid two">
      <section class="card">
        <h3>Label Health</h3>
        <ul>
          <li>Articles with 0 labels: <strong>${result.labelHealth.zeroLabel}</strong> (${result.labelHealth.zeroLabelPct}% of scanned)</li>
          <li>Unique labels in use: <strong>${result.labelHealth.uniqueLabels}</strong></li>
          <li>Top labels: ${escapeHtml(topLabels)}</li>
        </ul>
        <h3 style="margin-top:18px;">Biggest Systemic Gaps</h3>
        ${gapsMarkup}
      </section>
      <section class="card">
        <h3>Top Actions (Impact-first)</h3>
        ${actionsMarkup}
      </section>
    </div>

    <section class="card">
      <h3>Label Taxonomy — Recommendations</h3>
      <p><strong>Canonical set (draft):</strong></p>
      <div>${canonicalMarkup}</div>
      ${synonymMarkup ? `<p style="margin-top:12px;"><strong>Synonyms to merge:</strong></p>${synonymMarkup}` : ""}
      ${retireMarkup}
      ${namespaceMarkup}
    </section>

    <section class="card">
      <h3>Exemplars (Before → After Micro-edits)</h3>
      ${exemplarsMarkup}
    </section>

    <section class="card">
      <h3>Appendix — Article Table</h3>
      <table>
        <thead>
          <tr><th>ID</th><th>Title</th><th>Labels (#)</th><th>CS Score</th><th>LLM Score</th><th>Updated</th></tr>
        </thead>
        <tbody>${appendixRows}</tbody>
      </table>
    </section>
  `;
}

function formatDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return escapeHtml(String(value));
  return date.toLocaleString();
}

function renderKnowledgeAssessment(project, { url = "", result = null, error = "", savedAt = null } = {}) {
  const placeholder = READINESS_PLACEHOLDERS[KNOWLEDGE_ASSESSMENT_SLUG];
  const llmStatus = llmConfigStatus();
  const keyWarning = llmStatus.ready
    ? ""
    : `<div class="flash info">Set <code>${escapeHtml(llmStatus.envVar)}</code> in your <code>.env</code> file to enable scoring with ${escapeHtml(llmStatus.model)}. <a href="${escapeHtml(llmStatus.keyUrl)}" target="_blank" rel="noopener">Get a key</a>.</div>`;
  const errorMarkup = error ? `<div class="flash error">${escapeHtml(error)}</div>` : "";
  const savedNote = result && savedAt
    ? `<p class="hint">Showing saved results from <strong>${escapeHtml(formatDateTime(savedAt))}</strong>${url ? ` for <code>${escapeHtml(url)}</code>` : ""}. Re-running updates the saved report.</p>`
    : "";
  const runButtonLabel = result ? "Re-run Assessment" : "Run Assessment";

  return pageChrome(project._req, placeholder.title, `
    <div class="breadcrumb"><a href="/">Flights</a> / <a href="/projects/${project.id}">${escapeHtml(project.project_name)}</a> / ${escapeHtml(placeholder.title)}</div>
    ${keyWarning}
    ${errorMarkup}
    <section class="card">
      <h1>${escapeHtml(placeholder.title)}</h1>
      <p>Run an AI-readiness audit of a public Zendesk Help Center. Enter the Help Center URL and we will score article quality and LLM readability, review label health, and suggest the highest-impact fixes.</p>
      <form method="post" action="/projects/${project.id}/readiness/${KNOWLEDGE_ASSESSMENT_SLUG}/run" onsubmit="kbRunning(this)">
        <label for="knowledge_source_url">Knowledge Source URL</label>
        <input id="knowledge_source_url" name="knowledge_source_url" type="text" inputmode="url"
          placeholder="https://acme.zendesk.com/hc/en-us" value="${escapeHtml(url)}" required autocomplete="off">
        <p class="hint">Paste a full Help Center URL — we will extract the subdomain automatically.</p>
        <div class="actions">
          <button type="submit" data-run-button>${runButtonLabel}</button>
          <span class="kb-running" data-run-status hidden>Running assessment… this can take up to a minute.</span>
          <a class="button secondary" href="/projects/${project.id}">Back to Flight details</a>
        </div>
      </form>
      ${savedNote}
    </section>
    ${result ? renderAssessmentResult(result) : ""}
    <script>
      function kbRunning(form) {
        var button = form.querySelector('[data-run-button]');
        var status = form.querySelector('[data-run-status]');
        if (button) { button.disabled = true; button.textContent = 'Running…'; }
        if (status) { status.hidden = false; }
      }
    </script>
  `);
}

app.get("/projects/:id/readiness/:module", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }

    if (req.params.module === KNOWLEDGE_ASSESSMENT_SLUG) {
      project._req = req;
      const saved = await getKnowledgeAssessment(project.id);
      res.send(renderKnowledgeAssessment(project, {
        url: saved?.source_url || "",
        result: saved?.result || null,
        savedAt: saved?.updated_at || null
      }));
      return;
    }

    const placeholder = READINESS_PLACEHOLDERS[req.params.module] || {
      title: "Configuration option",
      description: "Placeholder for this Flight configuration option."
    };

    res.send(pageChrome(req, placeholder.title, `
      <div class="breadcrumb"><a href="/">Flights</a> / <a href="/projects/${project.id}">${escapeHtml(project.project_name)}</a> / ${escapeHtml(placeholder.title)}</div>
      <section class="card">
        <h1>${escapeHtml(placeholder.title)}</h1>
        <p>${escapeHtml(placeholder.description)}</p>
        <p class="hint">This module is intentionally a placeholder for now.</p>
        <div class="actions">
          <a class="button secondary" href="/projects/${project.id}">Back to Flight details</a>
        </div>
      </section>
    `));
  } catch (error) {
    next(error);
  }
});

app.post(`/projects/:id/readiness/${KNOWLEDGE_ASSESSMENT_SLUG}/run`, requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }

    project._req = req;
    const url = (req.body.knowledge_source_url || "").trim();
    try {
      const result = await runKnowledgeAssessment(url, project);
      await saveKnowledgeAssessment(project.id, url, result.subdomain, result);
      const saved = await getKnowledgeAssessment(project.id);
      res.send(renderKnowledgeAssessment(project, { url, result, savedAt: saved?.updated_at || null }));
    } catch (assessmentError) {
      res.send(renderKnowledgeAssessment(project, { url, error: assessmentError.message }));
    }
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/details", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }

    await pool.query(
      `UPDATE projects
       SET project_name = $1,
           client = $2,
           account_executive = $3,
           arr_impact = NULLIF($4, '')::numeric,
           start_date = NULLIF($5, '')::date,
           end_date = NULLIF($6, '')::date,
           sfdc_opportunity_link = $7,
           updated_at = now()
       WHERE id = $8`,
      [
        req.body.project_name,
        req.body.client,
        req.body.account_executive || null,
        req.body.arr_impact || "",
        req.body.start_date || "",
        req.body.end_date || "",
        req.body.sfdc_opportunity_link || null,
        project.id
      ]
    );

    setFlash(req, "Flight details updated.", "success");
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/success-criteria", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }

    const criteria = parseSuccessCriteriaRows(req.body);
    await pool.query(
      "UPDATE projects SET success_criteria = $1::jsonb, updated_at = now() WHERE id = $2",
      [JSON.stringify(criteria), project.id]
    );

    setFlash(req, "Success criteria updated.", "success");
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/authorized-users", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }

    const email = normalizeEmail(req.body.email);
    if (!assertValidEmail(email)) throw new Error("Authorized user email is invalid.");
    if (email.endsWith("@zendesk.com")) throw new Error("Authorized users should use non-Zendesk emails.");

    await pool.query(
      `INSERT INTO project_authorized_users (project_id, name, email, role, access_enabled)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (project_id, email) DO UPDATE SET
         name = EXCLUDED.name,
         role = EXCLUDED.role,
         access_enabled = EXCLUDED.access_enabled`,
      [project.id, req.body.name, email, req.body.role || "Flight Crew", selectedValues(req.body.access_enabled).includes("true")]
    );
    setFlash(req, "Flight Crew saved.", "success");
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/authorized-users/:userId/access", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }

    await pool.query(
      "UPDATE project_authorized_users SET access_enabled = $1 WHERE project_id = $2 AND id = $3",
      [selectedValues(req.body.access_enabled).includes("true"), project.id, req.params.userId]
    );
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/authorized-users/:userId/delete", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }

    await pool.query(
      "DELETE FROM project_authorized_users WHERE project_id = $1 AND id = $2",
      [project.id, req.params.userId]
    );
    setFlash(req, "Flight Crew removed.", "success");
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

function moduleNav(project, active) {
  return `
    <div class="steps">
      <a class="step" href="/projects/${project.id}">Flight details</a>
      <a class="step ${active === "module1" ? "active" : ""}" href="${airtableConfigHref(project)}">Airtable Configuration</a>
      <a class="step ${active === "module2" ? "active" : ""}" href="${aiAgentConfigHref(project)}">AI Agent Configuration</a>
    </div>
  `;
}

app.get("/projects/:id/module1", requireUser, async (req, res, next) => {
  res.redirect(airtableConfigHref({ id: req.params.id }));
});

app.get("/projects/:id/readiness/:module/airtable-config", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }

    const config = await getConfig(project.id);
    const authorizedUsers = await getAuthorizedUsers(project.id);
    const currentModuleTitle = moduleTitle(req.params.module);
    let body = `
      ${renderBreadcrumb(project, [{ label: currentModuleTitle, href: readinessHref(project, req.params.module) }, { label: "Airtable Configuration" }])}
      ${moduleNav(project, "module1")}
      <section class="card">
        <h1>${escapeHtml(project.project_name)}</h1>
        ${projectSummary(project)}
      </section>
      ${canManageProject(project, req.user) ? renderAuthorizedUserManagement(project, authorizedUsers, true) : ""}
    `;

    if (!config?.encrypted_pat) {
      body += renderPatForm(project);
      res.send(pageChrome(req, "Advanced Bot: Airtable API", body));
      return;
    }

    const pat = decryptSecret(config.encrypted_pat);
    const bases = await fetchBases(pat);

    body += renderBaseSelection(project, bases);

    if (project.airtable_base_id) {
      const tables = await fetchTables(pat, project.airtable_base_id);
      body += renderTableSelection(project, tables);
      body += renderCreateTable(project);
    }

    if (project.airtable_base_id && project.airtable_table_name) {
      const sampleRecords = await fetchSampleRecords(pat, project.airtable_base_id, project.airtable_table_id || project.airtable_table_name);
      const sampleRow = sampleRecords[0]?.fields || config.sample_row || {};
      if (!sampleRecords.length && !Object.keys(sampleRow).length) {
        body += `
          <section class="card">
            <h2>Sample row required</h2>
            <p>The selected Airtable table does not have a row yet. Add one in Airtable, then refresh this page.</p>
          </section>
        `;
      } else {
        body += renderColumnSelection(project, sampleRow, config.selected_columns || []);
      }
    }

    res.send(pageChrome(req, "Advanced Bot: Airtable API", body));
  } catch (error) {
    next(error);
  }
});

function renderPatForm(project) {
  return `
    <section class="card">
      <h2>Step 1: Confirm Airtable account</h2>
      <p>Enter an Airtable Personal Access Token. The app will validate metadata access and store it encrypted in PostgreSQL.</p>
      <form method="post" action="/projects/${project.id}/airtable/pat">
        <label for="pat">Personal Access Token</label>
        <input id="pat" name="pat" type="password" required autocomplete="off">
        <p class="hint">For local testing, keep the PAT in your local environment. In production, the saved PAT is encrypted with <code>APP_SECRET</code>.</p>
        <div class="actions"><button type="submit">Validate and save</button></div>
      </form>
    </section>
  `;
}

function renderAuthorizedUserManagement(project, authorizedUsers, canManage = false) {
  const rows = authorizedUsers.map((user) => `
    <tr>
      <td>${escapeHtml(user.name)}</td>
      <td>${escapeHtml(user.email)}</td>
      <td>${escapeHtml(displayCrewRole(user.role))}</td>
      <td>
        ${canManage ? `
          <form method="post" action="/projects/${project.id}/authorized-users/${user.id}/access">
            <input type="hidden" name="access_enabled" value="false">
            <input type="checkbox" name="access_enabled" value="true" ${user.access_enabled ? "checked" : ""} onchange="this.form.requestSubmit()">
          </form>
        ` : `<input type="checkbox" ${user.access_enabled ? "checked" : ""} disabled>`}
      </td>
      <td>
        ${canManage ? `
          <form method="post" action="/projects/${project.id}/authorized-users/${user.id}/delete">
            <button class="trash-button" type="submit" title="Remove Flight Crew">&#128465;</button>
          </form>
        ` : ""}
      </td>
    </tr>
  `).join("");

  return `
    <section class="card">
      <div class="actions" style="justify-content: space-between; margin-top: 0;">
        <div>
          <h2>Flight Crew</h2>
        </div>
        ${canManage ? '<button type="button" class="secondary" onclick="document.getElementById(\'copilot-modal\').hidden = false">Add Flight Crew</button>' : ""}
      </div>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Access</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">No Flight Crew added yet.</td></tr>'}</tbody>
      </table>
      ${canManage ? `
        <div id="copilot-modal" class="modal-backdrop" hidden>
          <div class="modal">
            <h2>Add Flight Crew</h2>
            <form method="post" action="/projects/${project.id}/authorized-users">
              <div class="grid two">
                <div>
                  <label for="auth_name">Name</label>
                  <input id="auth_name" name="name" required>
                </div>
                <div>
                  <label for="auth_email">Email</label>
                  <input id="auth_email" name="email" type="email" required>
                </div>
                <div>
                  <label for="auth_role">Role</label>
                  <input id="auth_role" name="role" value="Flight Crew" required>
                </div>
                <div class="checkbox-list">
                  <label><input type="checkbox" name="access_enabled" value="true"> Access</label>
                </div>
              </div>
              <div class="actions">
                <button type="submit">Add Flight Crew</button>
                <button type="button" class="secondary" onclick="document.getElementById('copilot-modal').hidden = true">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      ` : ""}
    </section>
  `;
}

function renderBaseSelection(project, bases) {
  return `
    <section class="card">
      <h2>Step 2: Identify base</h2>
      <form method="post" action="/projects/${project.id}/airtable/base">
        <label for="base_id">Airtable base</label>
        <select id="base_id" name="base_id" required>
          <option value="">Select a base</option>
          ${bases.map((base) =>
            `<option value="${escapeHtml(base.id)}" data-name="${escapeHtml(base.name)}" ${project.airtable_base_id === base.id ? "selected" : ""}>${escapeHtml(base.name)} (${escapeHtml(base.id)})</option>`
          ).join("")}
        </select>
        <input type="hidden" id="base_name" name="base_name" value="${escapeHtml(project.airtable_base_name || "")}">
        <div class="actions"><button type="submit">Save base</button></div>
      </form>
      <script>
        document.getElementById("base_id")?.addEventListener("change", function () {
          const selected = this.options[this.selectedIndex];
          document.getElementById("base_name").value = selected ? selected.text.replace(/ \\(.+\\)$/, "") : "";
        });
      </script>
    </section>
  `;
}

function renderTableSelection(project, tables) {
  return `
    <section class="card">
      <h2>Select existing table</h2>
      <form method="post" action="/projects/${project.id}/airtable/table/select">
        <label for="table_id">Existing table</label>
        <select id="table_id" name="table_id" required>
          <option value="">Select a table</option>
          ${tables.map((table) =>
            `<option value="${escapeHtml(table.id)}" data-name="${escapeHtml(table.name)}" ${project.airtable_table_id === table.id ? "selected" : ""}>${escapeHtml(table.name)}</option>`
          ).join("")}
        </select>
        <input type="hidden" id="table_name" name="table_name" value="${escapeHtml(project.airtable_table_name || "")}">
        <div class="actions"><button type="submit">Use selected table</button></div>
      </form>
      <script>
        document.getElementById("table_id")?.addEventListener("change", function () {
          const selected = this.options[this.selectedIndex];
          document.getElementById("table_name").value = selected ? selected.text : "";
        });
      </script>
    </section>
  `;
}

function renderCreateTable(project) {
  return `
    <section class="card">
      <h2>Create new table</h2>
      <form method="post" action="/projects/${project.id}/airtable/table/create">
        <div class="grid two">
          <div>
            <label for="schema_type">Schema</label>
            <select id="schema_type" name="schema_type">
              <option value="cx">CX default</option>
              <option value="it">IT default</option>
              <option value="custom">Custom</option>
            </select>
          </div>
          <div>
            <label for="table_name">Table name</label>
            <input id="table_name" name="table_name" placeholder="My API Data" required>
          </div>
        </div>
        <div class="grid two" style="margin-top: 16px;">
          <div>
            <label for="custom_columns">Custom column names</label>
            <textarea id="custom_columns" name="custom_columns" placeholder="name&#10;DOB&#10;email"></textarea>
            <p class="hint">Only used for custom schema. No spaces allowed.</p>
          </div>
          <div>
            <label for="custom_samples">Custom sample data</label>
            <textarea id="custom_samples" name="custom_samples" placeholder="name <> john doe&#10;DOB <> 1/1/1980&#10;email <> john@example.com"></textarea>
          </div>
        </div>
        <div class="actions"><button type="submit">Create table and sample data</button></div>
      </form>
    </section>
  `;
}

function renderColumnSelection(project, sampleRow, selectedColumns) {
  const fields = Object.keys(sampleRow);
  return `
    <section class="card">
      <h2>Step 3: Select columns for AI Agent Configuration</h2>
      <p>Connection test succeeded. Select the key column and the values to save for the Advanced Bot Zendesk AI Agent guide.</p>
      <form method="post" action="/projects/${project.id}/airtable/columns">
        <label for="key_column">Key column</label>
        <select id="key_column" name="key_column" required>
          <option value="">Select a key column</option>
          ${fields.map((field) =>
            `<option value="${escapeHtml(field)}" ${project.airtable_key_column === field ? "selected" : ""}>${escapeHtml(field)}: ${escapeHtml(sampleRow[field])}</option>`
          ).join("")}
        </select>
        <div class="checkbox-list">
          ${fields.map((field) => `
            <label>
              <input type="checkbox" name="selected_columns" value="${escapeHtml(field)}" ${selectedColumns.includes(field) ? "checked" : ""}>
              <strong>${escapeHtml(field)}</strong> <span class="hint">${escapeHtml(sampleRow[field])}</span>
            </label>
          `).join("")}
        </div>
        <div class="actions">
          <button type="submit">Save selected columns</button>
          <a class="button secondary" href="${aiAgentConfigHref(project)}">Continue to Zendesk AI Agent guide</a>
        </div>
      </form>
    </section>
  `;
}

app.post("/projects/:id/airtable/pat", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    const pat = String(req.body.pat || "").trim();
    if (!pat) throw new Error("Airtable PAT is required.");
    await fetchBases(pat);
    await upsertAirtableConfig(project.id, { encrypted_pat: encryptSecret(pat) });
    setFlash(req, "Airtable PAT validated and saved securely.", "success");
    res.redirect(airtableConfigHref(project));
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/airtable/base", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    await pool.query(
      `UPDATE projects
       SET airtable_base_id = $1, airtable_base_name = $2, airtable_table_id = NULL,
           airtable_table_name = NULL, airtable_key_column = NULL, updated_at = now()
       WHERE id = $3`,
      [req.body.base_id, req.body.base_name || req.body.base_id, project.id]
    );
    setFlash(req, "Airtable base saved.", "success");
    res.redirect(airtableConfigHref(project));
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/airtable/table/select", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    const pat = await getAirtableToken(project.id);
    const records = await fetchSampleRecords(pat, project.airtable_base_id, req.body.table_id);
    if (!records.length) {
      throw new Error("Selected table must have at least one mock/sample row before continuing.");
    }
    await pool.query(
      `UPDATE projects
       SET airtable_table_id = $1, airtable_table_name = $2, airtable_key_column = NULL, updated_at = now()
       WHERE id = $3`,
      [req.body.table_id, req.body.table_name || req.body.table_id, project.id]
    );
    await upsertAirtableConfig(project.id, { sample_row: records[0].fields, selected_columns: [] });
    setFlash(req, "Airtable table selected and sample row confirmed.", "success");
    res.redirect(airtableConfigHref(project));
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/airtable/table/create", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    const pat = await getAirtableToken(project.id);
    const schemaType = req.body.schema_type || "cx";
    const fields = schemaType === "custom"
      ? parseCustomFields(req.body.custom_columns, req.body.custom_samples)
      : DEFAULT_SCHEMAS[schemaType].fields;

    if (!fields.length) throw new Error("At least one field is required.");
    const tableName = String(req.body.table_name || DEFAULT_SCHEMAS[schemaType]?.tableName || "New Table").trim();
    const table = await createAirtableTable(pat, project.airtable_base_id, tableName, fields);
    await createAirtableSampleRecord(pat, project.airtable_base_id, table.id || tableName, fields);
    const records = await fetchSampleRecords(pat, project.airtable_base_id, table.id || tableName);

    await pool.query(
      `UPDATE projects
       SET airtable_table_id = $1, airtable_table_name = $2, airtable_key_column = NULL, updated_at = now()
       WHERE id = $3`,
      [table.id || null, table.name || tableName, project.id]
    );
    await upsertAirtableConfig(project.id, {
      sample_row: records[0]?.fields || sampleRecord(fields),
      selected_columns: [],
      airtable_metadata: { createdTable: table, schemaType }
    });
    setFlash(req, "Airtable table and sample data created.", "success");
    res.redirect(airtableConfigHref(project));
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/airtable/columns", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canManageProject(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    const keyColumn = req.body.key_column;
    const selectedColumns = selectedValues(req.body.selected_columns);
    if (!keyColumn) throw new Error("Key column is required.");
    if (!selectedColumns.length) throw new Error("Select at least one column for the Zendesk AI Agent guide.");

    const pat = await getAirtableToken(project.id);
    const records = await fetchSampleRecords(pat, project.airtable_base_id, project.airtable_table_id || project.airtable_table_name);
    await pool.query("UPDATE projects SET airtable_key_column = $1, updated_at = now() WHERE id = $2", [keyColumn, project.id]);
    await upsertAirtableConfig(project.id, {
      selected_columns: selectedColumns,
      sample_row: records[0]?.fields || {}
    });
    setFlash(req, "Saved key column and selected fields for the Zendesk AI Agent guide.", "success");
    res.redirect(aiAgentConfigHref(project));
  } catch (error) {
    next(error);
  }
});

app.get("/projects/:id/module2", requireUser, async (req, res, next) => {
  const target = aiAgentConfigHref({ id: req.params.id });
  res.redirect(req.query.tab ? `${target}?tab=${encodeURIComponent(req.query.tab)}` : target);
});

app.get("/projects/:id/readiness/:module/ai-agent-config", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }
    if (!canAccessModule2(project, req.user)) {
      res.status(403).send(pageChrome(req, "Advanced Bot unavailable", `
        <section class="card">
          <h1>Advanced Bot unavailable</h1>
          <p>You can view this flight, but Advanced Bot access has not been enabled for collaborators.</p>
        </section>
      `));
      return;
    }

    const config = await getConfig(project.id);
    const selectedColumns = config?.selected_columns || [];
    const sampleRow = config?.sample_row || {};
    const activeTab = req.query.tab || "confirm";
    const currentModuleTitle = moduleTitle(req.params.module);

    res.send(pageChrome(req, "Advanced Bot: Zendesk AI Agent", `
      ${renderBreadcrumb(project, [{ label: currentModuleTitle, href: readinessHref(project, req.params.module) }, { label: "AI Agent Configuration" }])}
      ${moduleNav(project, "module2")}
      <section class="card">
        <h1>Zendesk AI Agent Configuration</h1>
        <p>Use these guided tabs to copy values from this app into Zendesk Actions > API Integrations > Add integration.</p>
      </section>
      ${renderModule2Tabs(project, selectedColumns, sampleRow, activeTab, req.params.module)}
    `));
  } catch (error) {
    next(error);
  }
});

function renderModule2Tabs(project, selectedColumns, sampleRow, activeTab, moduleSlug = "build-api-connection") {
  const tabs = [
    ["confirm", "SE Bot"],
    ["environment", "Environment"],
    ["auth", "Authorization and Headers"],
    ["request", "Request Parameters"],
    ["test", "Test Integration"],
    ["success", "Success Scenarios"]
  ];
  const content = {
    confirm: renderBotConfirmation(project, moduleSlug),
    environment: renderCopyPanel("Environment", [
      ["Environment", "Production"],
      ["Integration Name", `${project.project_name} Airtable Lookup`],
      ["Description", `Lookup ${project.client} data from Airtable for Zendesk AI Agent.`]
    ], "Placeholder for Zendesk environment screenshot."),
    auth: renderCopyPanel("Authorization and Headers", [
      ["Authorization type", "Bearer token"],
      ["Header key", "Authorization"],
      ["Header value", "Bearer <server-side-token-or-proxy-secret>"],
      ["Content-Type", "application/json"]
    ], "Placeholder for authorization and headers screenshot."),
    request: renderCopyPanel("Request Parameters", [
      ["Key", project.airtable_key_column || "Select a key column in Advanced Bot: Airtable API"],
      ["Type", "String"],
      ["Test value", sampleRow[project.airtable_key_column] || "Use a value from the Airtable sample row"],
      ["Required", "true"]
    ], "Placeholder for request parameters screenshot."),
    test: renderCopyPanel("Test Integration", [
      ["Instruction", "Run Test Integration and confirm the response is HTTP 200 before continuing."],
      ["Base", project.airtable_base_name || project.airtable_base_id || ""],
      ["Table", project.airtable_table_name || ""]
    ], "Placeholder for test integration screenshot."),
    success: renderSuccessScenarios(selectedColumns, sampleRow)
  };

  return `
    <section class="card tabs">
      <nav class="tabnav">
        ${tabs.map(([id, label]) =>
          `<a class="${activeTab === id ? "active" : ""}" href="${aiAgentConfigHref(project, moduleSlug)}?tab=${id}">${escapeHtml(label)}</a>`
        ).join("")}
      </nav>
      <div>${content[activeTab] || content.confirm}</div>
    </section>
  `;
}

function renderBotConfirmation(project, moduleSlug = "build-api-connection") {
  return `
    <h2>Step 1: SE Create Bot</h2>
    <p>Confirm that the SE has already built the Zendesk bot they want to use.</p>
    <form method="post" action="${aiAgentConfigHref(project, moduleSlug)}/bot-confirmation">
      <div class="checkbox-list">
        <label><input type="checkbox" name="confirmed" value="true" ${project.module2_bot_confirmed ? "checked" : ""}> Yes, the bot has been built.</label>
      </div>
      <div class="actions"><button type="submit">Save confirmation</button></div>
    </form>
  `;
}

function renderCopyPanel(title, rows, screenshotText) {
  return `
    <h2>${escapeHtml(title)}</h2>
    <p class="hint">${escapeHtml(screenshotText)}</p>
    ${rows.map(([label, value], index) => {
      const id = `copy-${crypto.createHash("md5").update(`${title}-${label}-${index}`).digest("hex")}`;
      return `
        <label>${escapeHtml(label)}</label>
        <div class="copy-row">
          <div class="copy-value" id="${id}">${escapeHtml(value)}</div>
          <button type="button" class="secondary" data-copy-target="${id}" onclick="copyText('${id}')">Copy</button>
        </div>
      `;
    }).join("")}
  `;
}

function renderSuccessScenarios(selectedColumns, sampleRow) {
  if (!selectedColumns.length) {
    return `
      <h2>Success Scenarios</h2>
      <p>Select Airtable columns in Advanced Bot: Airtable API before configuring success scenarios.</p>
    `;
  }
  return `
    <h2>Scenarios - Success</h2>
    <p>Use the column name as the key so the bot can identify the information. Copy each JSONata expression into Zendesk.</p>
    ${selectedColumns.map((column, index) => renderCopyPanel(`Column: ${column}`, [
      ["Key", column],
      ["Query", `data.records.fields.${column}`],
      ["Sample value", sampleRow[column] || ""]
    ], index === 0 ? "Placeholder for success scenario screenshot." : "")).join("")}
  `;
}

async function handleBotConfirmation(req, res, next) {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project || !canAccessModule2(project, req.user)) {
      res.status(403).send("Not allowed.");
      return;
    }
    await pool.query(
      "UPDATE projects SET module2_bot_confirmed = $1, updated_at = now() WHERE id = $2",
      [req.body.confirmed === "true", project.id]
    );
    setFlash(req, "Bot confirmation saved.", "success");
    res.redirect(aiAgentConfigHref(project, req.params.module || "build-api-connection"));
  } catch (error) {
    next(error);
  }
}

app.post("/projects/:id/module2/bot-confirmation", requireUser, handleBotConfirmation);
app.post("/projects/:id/readiness/:module/ai-agent-config/bot-confirmation", requireUser, handleBotConfirmation);

app.use((error, req, res, _next) => {
  console.error(error);
  const message = error.message || "Unexpected error.";
  if (req.user) {
    res.status(500).send(pageChrome(req, "Error", `
      <section class="card">
        <h1>Something went wrong</h1>
        <p>${escapeHtml(message)}</p>
        <div class="actions"><a class="button secondary" href="/">Back to flights</a></div>
      </section>
    `));
  } else {
    res.status(500).send(layout("Error", `<section class="card narrow"><h1>Error</h1><p>${escapeHtml(message)}</p></section>`));
  }
});

migrate()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to start application:", error.message);
    process.exit(1);
  });
