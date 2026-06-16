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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(project_id, email)
    );

    CREATE TABLE IF NOT EXISTS project_airtable_config (
      project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      encrypted_pat TEXT,
      selected_columns JSONB NOT NULL DEFAULT '[]'::jsonb,
      sample_row JSONB NOT NULL DEFAULT '{}'::jsonb,
      airtable_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
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
  const email = readIdentity(req);
  if (!email) {
    res.status(401).send(layout("Sign in required", `
      <section class="card narrow">
        <h1>Sign in required</h1>
        <p>This app expects Pomerium to provide <code>X-Pomerium-Claim-Email</code>.</p>
        <p>For local development, set <code>DEV_EMAIL</code> or visit <code>/?devEmail=user@zendesk.com</code>.</p>
      </section>
    `));
    return;
  }

  req.user = {
    email,
    isAdmin: email === ADMIN_EMAIL,
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
  return layout(title, `
    <header class="topbar">
      <div class="header-left">
        <a class="brand" href="/">Zendesk Flight School</a>
        <a class="header-link" href="/">Back to flights</a>
      </div>
      <nav>
        <span>${escapeHtml(req.user.email)}</span>
        ${req.user.isAdmin ? '<span class="pill">App Admin</span>' : ""}
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
        .header-link {
          color: var(--zd-subtle);
          font-size: 14px;
          font-weight: 650;
          text-decoration: none;
        }
        .header-link:hover { color: var(--zd-green); }
        .topbar nav {
          align-items: center;
          color: var(--zd-subtle);
          display: flex;
          gap: 12px;
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
        .detail-hero .status-badge {
          position: absolute;
          right: 24px;
          top: 24px;
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
          font-weight: 650;
          margin: 0;
        }
        .mission-layout {
          display: grid;
          gap: 24px;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        }
        .mission-group {
          border: 1px solid var(--zd-border);
          border-radius: 10px;
          margin-bottom: 12px;
          overflow: hidden;
        }
        .mission-group summary {
          cursor: pointer;
          font-weight: 750;
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
        .mission-option {
          align-items: center;
          border: 1px solid var(--zd-border);
          border-radius: 8px;
          color: var(--zd-text);
          display: flex;
          justify-content: space-between;
          padding: 12px 14px;
          text-decoration: none;
        }
        .mission-option:hover {
          background: #f3f5f5;
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
        @media (max-width: 800px) {
          .grid.two, .grid.three, .toolbar, .tabs, .mission-layout { grid-template-columns: 1fr; }
          .topbar { align-items: flex-start; flex-direction: column; gap: 8px; padding: 16px; }
          .header-left { align-items: flex-start; flex-direction: column; gap: 6px; }
          .container { padding: 16px; }
          .detail-hero h1 { margin-right: 0; }
          .detail-hero .status-badge { position: static; margin-bottom: 12px; }
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
    start_date: "p.start_date",
    end_date: "p.end_date",
    arr_impact: "p.arr_impact",
    created_at: "p.created_at"
  };
  const sortColumn = allowedSorts[options.sort] || "p.updated_at";
  const sortDir = options.dir === "asc" ? "ASC" : "DESC";

  const result = user.isAdmin
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
          WHERE pau.project_id = p.id AND lower(pau.email) = lower($1)
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
        WHERE pau.project_id = p.id AND lower(pau.email) = lower($2)
      ) AS is_authorized_user
     FROM projects p
     WHERE p.id = $1`,
    [projectId, user.email]
  );
  const project = result.rows[0];
  if (!project) return null;

  const canAccess = user.isAdmin || normalizeEmail(project.owner_email) === user.email || project.is_authorized_user;
  return canAccess ? project : null;
}

function canManageProject(project, user) {
  return user.isAdmin || normalizeEmail(project.owner_email) === user.email;
}

function canAccessModule2(project, user) {
  if (user.isAdmin || normalizeEmail(project.owner_email) === user.email) return true;
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
      <div><dt>ARR Impact</dt><dd>${escapeHtml(project.arr_impact ?? "")}</dd></div>
      <div><dt>Start Date</dt><dd>${escapeHtml(formatDate(project.start_date))}</dd></div>
      <div><dt>End Date</dt><dd>${escapeHtml(formatDate(project.end_date))}</dd></div>
      <div><dt>Account Executive</dt><dd>${escapeHtml(project.account_executive || "")}</dd></div>
    </dl>
  `;
}

function formatDate(value) {
  return value ? String(value).slice(0, 10) : "";
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
  const successCriteria = Array.isArray(project.success_criteria) ? project.success_criteria : [];
  return `
    <div class="breadcrumb"><a href="/">Flights</a> / ${escapeHtml(project.project_name)}</div>
    <section class="card detail-hero">
      ${renderStatusBadge(project)}
      <h1>${escapeHtml(project.project_name)}</h1>
      <dl class="grid three detail-list">
        <div><dt>Use case</dt><dd>${escapeHtml(project.client)}</dd></div>
        <div><dt>SFDC account</dt><dd>${project.sfdc_account_link ? `<a href="${escapeHtml(project.sfdc_account_link)}">${escapeHtml(project.sfdc_account_link)}</a>` : "Not provided"}</dd></div>
        <div><dt>SFDC opportunity</dt><dd>${project.sfdc_opportunity_link ? `<a href="${escapeHtml(project.sfdc_opportunity_link)}">${escapeHtml(project.sfdc_opportunity_link)}</a>` : "Not provided"}</dd></div>
        <div><dt>Your role</dt><dd>${escapeHtml(userRoleForFlight(project, user))}</dd></div>
        <div><dt>Account executive</dt><dd>${escapeHtml(project.account_executive || "Not provided")}</dd></div>
        <div><dt>ARR impact</dt><dd>${escapeHtml(project.arr_impact ?? "Not provided")}</dd></div>
        <div><dt>Start date</dt><dd>${escapeHtml(formatDate(project.start_date) || "Not provided")}</dd></div>
        <div><dt>End date</dt><dd>${escapeHtml(formatDate(project.end_date) || "Not provided")}</dd></div>
        <div><dt>Success criteria</dt><dd>${escapeHtml(successCriteria.join("; ") || "Not provided")}</dd></div>
      </dl>
    </section>
  `;
}

function readinessHref(project, slug) {
  return `/projects/${project.id}/readiness/${encodeURIComponent(slug)}`;
}

function renderMissionControl(project) {
  const groups = [
    {
      title: "Basic Bot Configuration",
      open: true,
      options: [
        { label: "Option 1", href: readinessHref(project, "basic-option-1") },
        { label: "Option 2", href: readinessHref(project, "basic-option-2") }
      ]
    },
    {
      title: "Advanced Bot Configuration",
      open: false,
      options: [
        { label: "Option 1", href: readinessHref(project, "advanced-option-1") },
        { label: "Airtable API + Zendesk AI Agent setup", href: `/projects/${project.id}/module1` },
        { label: "Option 2", href: readinessHref(project, "advanced-option-2") }
      ]
    },
    {
      title: "Copilot Configuration",
      open: false,
      options: [
        { label: "Option 1", href: readinessHref(project, "copilot-option-1") },
        { label: "Option 2", href: readinessHref(project, "copilot-option-2") }
      ]
    }
  ];

  return `
    <div class="mission-layout">
      <section class="card">
        <h2>Mission Control</h2>
        <p class="hint">Choose a configuration path. Each group expands into available options.</p>
        ${groups.map((group) => `
          <details class="mission-group" ${group.open ? "open" : ""}>
            <summary>${escapeHtml(group.title)}</summary>
            <div class="mission-options">
              ${group.options.map((option) => `
                <a class="mission-option" href="${escapeHtml(option.href)}">
                  <span>${escapeHtml(option.label)}</span>
                  <span>Open</span>
                </a>
              `).join("")}
            </div>
          </details>
        `).join("")}
      </section>
      <section class="card">
        <h2>Readiness checklist</h2>
        <ul class="checklist">
          ${renderChecklistItem("Flight created", true)}
          ${renderChecklistItem("Airtable table provisioned / bound", Boolean(project.airtable_table_name))}
          ${renderChecklistItem("Key column selected", Boolean(project.airtable_key_column))}
          ${renderChecklistItem("JSONata output schema saved", Boolean(project.airtable_key_column))}
          ${renderChecklistItem("AI agent bot created in Zendesk", Boolean(project.module2_bot_confirmed))}
          ${renderChecklistItem("API connection tested", false)}
          ${renderChecklistItem("Client collaborator invited", false)}
        </ul>
      </section>
    </div>
  `;
}

function renderChecklistItem(label, done) {
  return `<li><span class="check-dot ${done ? "done" : ""}">${done ? "&#10003;" : ""}</span><span>${escapeHtml(label)}</span></li>`;
}

const READINESS_PLACEHOLDERS = {
  "basic-option-1": { title: "Basic Bot Configuration - Option 1", description: "Placeholder for the first Basic Bot configuration path." },
  "basic-option-2": { title: "Basic Bot Configuration - Option 2", description: "Placeholder for the second Basic Bot configuration path." },
  "advanced-option-1": { title: "Advanced Bot Configuration - Option 1", description: "Placeholder for an additional Advanced Bot configuration path." },
  "advanced-option-2": { title: "Advanced Bot Configuration - Option 2", description: "Placeholder for an additional Advanced Bot configuration path." },
  "copilot-option-1": { title: "Copilot Configuration - Option 1", description: "Placeholder for the first Copilot configuration path." },
  "copilot-option-2": { title: "Copilot Configuration - Option 2", description: "Placeholder for the second Copilot configuration path." }
};

app.get("/", requireUser, async (req, res, next) => {
  try {
    const sort = req.query.sort || "updated_at";
    const dir = req.query.dir === "asc" ? "asc" : "desc";
    const filter = req.query.filter || "";
    const projects = await listVisibleProjects(req.user, { sort, dir, filter });
    const rows = projects.map((project) => `
      <tr class="clickable" onclick="goTo('/projects/${project.id}')">
        <td><strong>${escapeHtml(project.project_name)}</strong><div class="hint">${escapeHtml(project.client)}</div></td>
        <td>${escapeHtml(project.owner_email)}</td>
        <td>${escapeHtml(project.account_executive || "")}</td>
        <td>${escapeHtml(project.arr_impact ?? "")}</td>
        <td>${escapeHtml(formatDate(project.start_date))}</td>
        <td>${renderStatusBadge(project)}</td>
      </tr>
    `).join("");

    res.send(pageChrome(req, "Flights", `
      <section class="card">
        <div class="actions" style="justify-content: space-between; margin-top: 0;">
          <div>
            <h1>Flights</h1>
            <p class="hint">Select a flight to open Flight details and Mission Control.</p>
          </div>
          <a class="button" href="/projects/new">New flight</a>
        </div>
        <form class="toolbar" method="get" action="/">
          <div>
            <label for="filter">Filter</label>
            <input id="filter" name="filter" value="${escapeHtml(filter)}" placeholder="Flight, client, owner, or AE">
          </div>
          <div>
            <label for="sort">Sort by</label>
            <select id="sort" name="sort">
              ${["project_name", "client", "owner_email", "start_date", "end_date", "arr_impact", "created_at"].map((item) =>
                `<option value="${item}" ${sort === item ? "selected" : ""}>${escapeHtml(item.replace(/_/g, " "))}</option>`
              ).join("")}
            </select>
          </div>
          <div>
            <label for="dir">Direction</label>
            <select id="dir" name="dir">
              <option value="desc" ${dir === "desc" ? "selected" : ""}>Desc</option>
              <option value="asc" ${dir === "asc" ? "selected" : ""}>Asc</option>
            </select>
          </div>
          <button type="submit">Apply</button>
        </form>
        <table>
          <thead>
            <tr>
              <th>Flight</th>
              <th>Owner</th>
              <th>AE</th>
              <th>ARR Impact</th>
              <th>Start</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="6">No flights found.</td></tr>'}</tbody>
        </table>
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
            <label for="owner_email">Flight owner Zendesk email</label>
            <input id="owner_email" name="owner_email" type="email" value="${escapeHtml(req.user.email)}" required>
          </div>
          <div>
            <label for="client">Client</label>
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
            <label for="arr_impact">ARR impact</label>
            <input id="arr_impact" name="arr_impact" type="number" step="0.01">
          </div>
          <div>
            <label for="sfdc_account_link">SFDC account link</label>
            <input id="sfdc_account_link" name="sfdc_account_link" type="url">
          </div>
          <div>
            <label for="sfdc_opportunity_link">SFDC opportunity link</label>
            <input id="sfdc_opportunity_link" name="sfdc_opportunity_link" type="url">
          </div>
        </div>
        <div class="grid two" style="margin-top: 16px;">
          <div>
            <label for="success_criteria">Success criteria</label>
            <textarea id="success_criteria" name="success_criteria" placeholder="One success criterion per line"></textarea>
          </div>
          <div>
            <label for="authorized_users">Collaborators</label>
            <textarea id="authorized_users" name="authorized_users" placeholder="Name, non-zendesk-email@example.com"></textarea>
            <p class="hint">One user per line. Authorized users can see only flights where they are listed.</p>
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

    const ownerEmail = normalizeEmail(req.body.owner_email);
    if (!assertValidEmail(ownerEmail) || !ownerEmail.endsWith("@zendesk.com")) {
      throw new Error("Flight owner must be a valid Zendesk email address.");
    }

    const authorizedUsers = parseAuthorizedUsers(req.body.authorized_users);
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
          JSON.stringify(parseSuccessCriteria(req.body.success_criteria)),
          req.body.account_executive || null,
          req.body.arr_impact || "",
          req.body.sfdc_account_link || null,
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
    res.send(pageChrome(req, `${project.project_name} Flight`, `
      ${renderFlightHero(project, req.user)}
      ${renderMissionControl(project)}
      ${renderAuthorizedUserManagement(project, authorizedUsers, canManageProject(project, req.user))}
    `));
  } catch (error) {
    next(error);
  }
});

app.get("/projects/:id/readiness/:module", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
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
      `INSERT INTO project_authorized_users (project_id, name, email)
       VALUES ($1, $2, $3)
       ON CONFLICT (project_id, email) DO UPDATE SET name = EXCLUDED.name`,
      [project.id, req.body.name, email]
    );
    setFlash(req, "Authorized user saved.", "success");
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
    setFlash(req, "Authorized user removed.", "success");
    res.redirect(`/projects/${project.id}`);
  } catch (error) {
    next(error);
  }
});

function moduleNav(project, active) {
  return `
    <div class="steps">
      <a class="step" href="/projects/${project.id}">Flight details</a>
      <a class="step ${active === "module1" ? "active" : ""}" href="/projects/${project.id}/module1">Advanced Bot: Airtable API</a>
      <a class="step ${active === "module2" ? "active" : ""}" href="/projects/${project.id}/module2">Advanced Bot: Zendesk AI Agent</a>
    </div>
  `;
}

app.get("/projects/:id/module1", requireUser, async (req, res, next) => {
  try {
    const project = await getProject(req.params.id, req.user);
    if (!project) {
      res.status(404).send(pageChrome(req, "Flight not found", `<section class="card"><h1>Flight not found</h1></section>`));
      return;
    }

    const config = await getConfig(project.id);
    const authorizedUsers = await getAuthorizedUsers(project.id);
    let body = `
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
      <td>
        ${canManage ? `
          <form method="post" action="/projects/${project.id}/authorized-users/${user.id}/delete">
            <button class="danger" type="submit">Remove</button>
          </form>
        ` : '<span class="pill">Invited</span>'}
      </td>
    </tr>
  `).join("");

  return `
    <section class="card">
      <div class="actions" style="justify-content: space-between; margin-top: 0;">
        <div>
          <h2>Collaborators</h2>
          <p class="hint">These non-Zendesk users can see only this flight. Advanced Bot access depends on the flight flag.</p>
        </div>
        ${canManage ? '<span class="pill">Invite enabled</span>' : ""}
      </div>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Status</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3">No collaborators invited yet.</td></tr>'}</tbody>
      </table>
      ${canManage ? `<form method="post" action="/projects/${project.id}/authorized-users" style="margin-top: 16px;">
        <div class="grid two">
          <div>
            <label for="auth_name">Name</label>
            <input id="auth_name" name="name" required>
          </div>
          <div>
            <label for="auth_email">Non-Zendesk email</label>
            <input id="auth_email" name="email" type="email" required>
          </div>
        </div>
        <div class="actions"><button type="submit">Add authorized user</button></div>
      </form>` : ""}
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
          <a class="button secondary" href="/projects/${project.id}/module2">Continue to Zendesk AI Agent guide</a>
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
    res.redirect(`/projects/${project.id}/module1`);
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
    res.redirect(`/projects/${project.id}/module1`);
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
    res.redirect(`/projects/${project.id}/module1`);
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
    res.redirect(`/projects/${project.id}/module1`);
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
    res.redirect(`/projects/${project.id}/module2`);
  } catch (error) {
    next(error);
  }
});

app.get("/projects/:id/module2", requireUser, async (req, res, next) => {
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

    res.send(pageChrome(req, "Advanced Bot: Zendesk AI Agent", `
      ${moduleNav(project, "module2")}
      <section class="card">
        <h1>Zendesk AI Agent Configuration</h1>
        <p>Use these guided tabs to copy values from this app into Zendesk Actions > API Integrations > Add integration.</p>
      </section>
      ${renderModule2Tabs(project, selectedColumns, sampleRow, activeTab)}
    `));
  } catch (error) {
    next(error);
  }
});

function renderModule2Tabs(project, selectedColumns, sampleRow, activeTab) {
  const tabs = [
    ["confirm", "SE Bot"],
    ["environment", "Environment"],
    ["auth", "Authorization and Headers"],
    ["request", "Request Parameters"],
    ["test", "Test Integration"],
    ["success", "Success Scenarios"]
  ];
  const content = {
    confirm: renderBotConfirmation(project),
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
          `<a class="${activeTab === id ? "active" : ""}" href="/projects/${project.id}/module2?tab=${id}">${escapeHtml(label)}</a>`
        ).join("")}
      </nav>
      <div>${content[activeTab] || content.confirm}</div>
    </section>
  `;
}

function renderBotConfirmation(project) {
  return `
    <h2>Step 1: SE Create Bot</h2>
    <p>Confirm that the SE has already built the Zendesk bot they want to use.</p>
    <form method="post" action="/projects/${project.id}/module2/bot-confirmation">
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

app.post("/projects/:id/module2/bot-confirmation", requireUser, async (req, res, next) => {
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
    res.redirect(`/projects/${project.id}/module2`);
  } catch (error) {
    next(error);
  }
});

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
