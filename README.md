# Zendesk Flight School

Accelerating AI Wins with Frictionless APIs.

## Problem

Right now, API integration is a major roadblock during critical sales cycles.

The friction: Customers struggle to test API connections inside our AI bots, and our Sales Engineers (SEs) have varying levels of technical comfort guiding them through it.

The risk: This creates a bottleneck for AI trials and Proof of Concepts (PoCs), directly risking revenue to competitors who offer heavier technical hand-holding.

## Solution

We’ve built a tool that democratizes API configuration. It enables anyone with basic Zendesk knowledge to build, test, and share a working API connection using real, third-party data.

## Intended Outcomes

Empowered Sales Engineers: Shifts our SEs from tech-support bottlenecks to strategic advisors, allowing them to confidently showcase advanced capabilities without needing to deeply hardcode configurations.

Faster Deal Velocity: Removes the primary blocker for AI trials, letting customers instantly experience the power of our bots and shortening the sales cycle.

Flexible Deployment: Build a tool that can be used both by Zendesk SEs as well as clients.

The bottom line: We are turning a technical hurdle into a repeatable competitive advantage, making it easier for our Sales Engineers to sell and faster for our customers to buy.

## App Overview

Single-file Express app for managing flights, configuring Airtable data, and guiding Zendesk AI Agent API integration setup.

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

`chines@zendesk.com` is the only app admin and can see all flights.
