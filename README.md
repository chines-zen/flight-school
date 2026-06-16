# Zendesk Flight School

Single-file Express app for managing projects, configuring Airtable data, and guiding Zendesk AI Agent API integration setup.

## Local Setup

1. Install dependencies:

   ```sh
   npm install
   ```

2. Copy `.env.example` to `.env` and set:

   - `DB_USER`
   - `DB_PASSWORD`
   - `DB_HOST`
   - `DB_NAME`
   - `DB_PORT`
   - `APP_SECRET`

3. Start the app:

   ```sh
   npm run dev
   ```

The server listens on `process.env.PORT` or defaults to `8080`.

## Authentication

Production authentication expects Pomerium to provide `X-Pomerium-Claim-Email`.

For local development only, the app accepts `DEV_EMAIL`, `X-Dev-Email`, or a `?devEmail=user@zendesk.com` query parameter.

## Airtable PAT Storage

Airtable Personal Access Tokens are encrypted before being saved in PostgreSQL using `APP_SECRET`. Use a long, random `APP_SECRET` in production.

## App Admin

`chines@zendesk.com` is the only app admin and can see all projects.
