# User Guide

## Getting Started

### 1. Installation

Follow the [Deployment Guide](Deployment.md) to set up SentinelScan locally or access your hosted instance.

The application runs at `http://localhost:3000` by default.

---

### 2. Creating an Account

Navigate to the **Sign Up** page at `/signup`.

**Required fields:**
- Full name
- Email address
- Password (minimum 8 characters)

After registering, a **verification email** is sent to your address. Click the link in the email to verify and activate your account.

> **Development mode:** If `DEV_BYPASS_EMAIL_VERIFICATION=true` is set (local development only), your account is auto-verified and no email is sent.

---

### 3. Logging In

Navigate to `/login` and enter your email and password.

**Google OAuth:** Click **Continue with Google** to sign in with your Google account. No password required for Google-authenticated accounts.

After login you are redirected to the **Dashboard**.

---

## Dashboard

The dashboard is your home screen. It provides an at-a-glance view of your security posture across all scans.

**What you see:**
- **Security Score** — circular progress ring showing the score from your most recent completed scan (0–100)
- **Grade** — letter grade corresponding to the score
- **Finding Counts** — Critical / High / Medium / Low finding counts from your latest scan
- **Recent Scans** — the 5 most recent scans with status badges
- **Quick Scan** — URL input to start a new scan without navigating away
- **Notifications** — unread alerts (scan complete, scan failed, etc.)

---

## Starting a Scan

### Via the Scan Page

1. Click **Scan** in the left sidebar
2. Enter the target URL in the input field
   - Example: `https://example.com`
   - The `https://` prefix is added automatically if omitted
3. Click **Start Scan**

**What happens next:**
- The scan is immediately enqueued in the background job queue
- You are shown a real-time progress screen

### Restrictions

- You can only scan **public-facing websites** — private/internal IPs are blocked for security
- You are limited to **2 active scans simultaneously** (pending or running)
- The scan rate limit is **10 scans per hour**
- Scanning takes 15–60 seconds depending on the target

---

## Live Scan Progress

Once a scan is enqueued, the progress screen shows:

1. **Progress bar** — updates in real time as each stage completes
2. **Current stage** — e.g. "SSL/TLS Analysis", "Technology Detection"
3. **Stage timeline** — all stages listed with checkmarks as they complete
4. **Status messages** — e.g. "Found 3 header issues", "Detected 4 technologies"

Stages in order:
1. DNS Analysis (Stage 1)
2. SSL/TLS Check (Stage 2)
3. Security Headers & Cookies (Stage 3)
4. Technology Detection (Stage 4)
5. CVE Database Lookup & EOL Lifecycle (Stage 5)
6. External Exposure Deep Analysis (Stage 5e — 45 detectors across 12 domains)
7. Content & Crawler Analysis (Stage 6)
8. OWASP Top 10:2025 Assessment (Stage 7)
9. Scoring & Report Generation (Stage 8)

When the scan completes, you are automatically redirected to the full report.

### Cancelling a Scan

Click the **Cancel** button during an active scan to stop it. Cancellation takes effect at the next stage boundary (cooperative inter-stage cancellation). No report is generated for a cancelled scan.

---

## Reading Reports

### Report Overview

The report header shows:
- **Score ring** — large circular visualization (green = safe, yellow = moderate, red = critical)
- **Grade** — A+ through F
- **Risk level** — Critical / High / Medium / Low
- **Scan date and target URL**

### Findings Table

The findings table lists every issue detected across all 82 registered detectors. You can:

- **Filter by severity** — click severity chips (Critical, High, Medium, Low, Info)
- **Filter by category** — use the category dropdown (Headers, SSL, DNS, Tech, Exposure, OWASP)
- **Search** — type to search by title or description
- **Sort** — click column headers

Click any finding row to expand it and see:
- Full description, problem statement, and impact analysis
- Machine-verifiable evidence (headers, cipher negotiation, DNS records, or redacted secret strings)
- CVSS score, CVE ID, and CWE ID
- OWASP Top 10:2025 mapping and MITRE ATT&CK technique
- Sequential fix steps with copy-ready configuration snippets (Nginx, Apache, Express)
- Official RFC and documentation reference links

### Score Breakdown

The score breakdown section shows each category's score as a colored progress bar:
- 🟢 Green — ≥ 80%
- 🟡 Yellow — 50–79%
- 🔴 Red — < 50%

### Tech Stack

The Tech Stack card lists every technology detected, organized by category (Web Server, CMS, JavaScript Framework, etc.). Version numbers and EOL flags are shown when detected.

### SSL/TLS Details

Shows:
- Certificate subject and issuer
- Days until expiry
- TLS version in use
- Cipher suite
- Subject Alternative Names

### DNS Analysis

Shows:
- SPF record (if present)
- DMARC policy (if present)
- DKIM selector status
- MX and TXT records

---

## Sentinel Intelligence — Security Assistant

SentinelScan embeds a contextual AI security analyst powered by Google Gemini 3.6 Flash. Sentinel Intelligence is grounded in scan evidence and helps operators understand findings without speculative guessing.

### How to Use Sentinel Intelligence
1. **Ask Sentinel Floating Button**: Click the **Ask Sentinel** floating button in the bottom-right corner to open the sliding analyst panel.
2. **Contextual Finding Explanation**: In any finding card or drawer, click **Explain with AI** to immediately prompt Sentinel Intelligence with the specific finding, observed evidence, and remediation steps.
3. **Conversational Follow-Up**: Ask natural follow-up questions (e.g., *"How do I configure this CSP directive for an Nginx reverse proxy?"*).
4. **Rate Limits**: AI queries are rate-limited to **20 requests per hour per user** via a sliding-window tracker.

---

## Circle to Sentinel — Visual Region Inspection

Circle to Sentinel allows you to select any portion of the SentinelScan interface and have the AI analyze it visually.

### How to Use Circle to Sentinel
1. **Shortcut or Button**: Press `Ctrl+Shift+S` (Windows/Linux) or `Cmd+Shift+S` (macOS), or click the visual inspect button.
2. **Select UI Region**: Drag a selection box over any UI element (a score ring, finding card, cipher list, or chart).
3. **Automatic Analysis**: Releasing the mouse opens Ask Sentinel with the prompt *"Analyzing selected area..."*. Sentinel Intelligence receives the cropped viewport screenshot, intersecting DOM text, and scan findings.
4. **Privacy & Security**: Circle to Sentinel captures only the SentinelScan browser interface—never other desktop windows or tabs. Visual context is held in server memory for inference only and is never stored to disk or database.

---

## Downloading Reports

From any report page, you can export your findings:
- **Download PDF**: Generates a professional ReportLab PDF report (Executive Summary or comprehensive Technical Report) with sensitive data redacted.
- **Download JSON**: Generates a machine-readable JSON export for SIEM integration or compliance archival.

---

## Scan History

Navigate to **History** in the sidebar to see all your past scans.

**Filters available:**
- Status (all, completed, failed, cancelled)
- Date range
- URL search

---

## OWASP View

The **OWASP** page groups all findings from your reports by OWASP Top 10:2025 category (A01 through A10). This helps you understand which OWASP risks are most prevalent across your assets.

---

## Notifications

In-app notifications appear in the sidebar notification bell. You receive notifications when:
- A scan completes successfully
- A scan fails (with error details)
- A scan is cancelled

Click any notification to navigate to the relevant report. Click **Mark all read** to clear the unread badge.

---

## Profile and Usage

### Profile

Navigate to **Profile** to:
- Update your display name
- Change your password
- View your account creation date and role

### Rate Limits & Usage

- **Concurrent Scans**: Up to 2 active scans running concurrently.
- **Hourly Scan Quota**: Up to 10 scans created per hour.
- **AI Quota**: Up to 20 Sentinel Intelligence requests per hour.

---

## Troubleshooting

### "Failed to load dashboard data"

- Check that you are logged in with a verified account
- Try refreshing the page
- Check browser console for network errors
- If the API is running, verify `/api/health` returns `200`

### Scan stuck at 0% or pending indefinitely

- The ARQ worker may not be running
- Check `/api/readiness` — if `worker.status` is `unknown`, start the worker:
  ```bash
  python run_worker.py
  ```
- After a grace period, the reconciliation cron will mark stuck scans as `failed`

### Scan shows "Failed"

- Check the error message in the scan detail view
- Common causes: target URL unreachable, timeout, DNS resolution failure
- Re-scan the target — scan failures are not permanent

### "Cannot scan this target" (SSRF)

- SentinelScan cannot scan `localhost`, `127.0.0.1`, or private network addresses
- This is a security restriction; scan only public-facing websites

### PDF download fails

- Ensure the report is completed (not pending/running/failed)
- Try again — PDF generation is on-demand and occasional timeouts occur for large reports

### Login fails even with correct credentials

- Verify your email address using the link sent on registration
- Check spam/junk folder for the verification email
- Use **Forgot Password** to reset if you've lost your password

---

## Logging Out

Click your avatar or name in the sidebar and select **Logout**. This:
1. Revokes your access token immediately (added to Redis blacklist)
2. Clears tokens from your browser
3. Redirects you to the login page

For security, log out when using shared or public computers.
