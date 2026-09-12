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
1. DNS Analysis
2. SSL/TLS Check
3. Security Headers
4. Technology Detection
5. CVE Database Lookup
6. Content Analysis
7. Generating Report

When the scan completes, you are automatically redirected to the full report.

### Cancelling a Scan

Click the **Cancel** button during an active scan to stop it. Cancellation takes effect at the next stage boundary (usually within 20 seconds). No report is generated for a cancelled scan.

---

## Reading Reports

### Report Overview

The report header shows:
- **Score ring** — large circular visualization (green = safe, yellow = moderate, red = critical)
- **Grade** — A+ through F
- **Risk level** — Critical / High / Medium / Low
- **Scan date and target URL**

### Findings Table

The findings table lists every issue detected. You can:

- **Filter by severity** — click severity chips (Critical, High, Medium, Low, Info)
- **Filter by category** — use the category dropdown
- **Search** — type to search by title or description
- **Sort** — click column headers

Click any finding row to expand it and see:
- Full description
- Evidence (what was observed)
- CVSS score and CVE ID (if applicable)
- OWASP Top 10 mapping
- MITRE ATT&CK technique
- Remediation steps
- Reference links

### Score Breakdown

The score breakdown section shows each category's score as a colored progress bar:
- 🟢 Green — ≥ 80%
- 🟡 Yellow — 50–79%
- 🔴 Red — < 50%

### Tech Stack

The Tech Stack card lists every technology detected, organized by category (Web Server, CMS, JavaScript Framework, etc.). Version numbers are shown when detected.

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
- DKIM detection status
- MX records

---

## Downloading PDF Reports

From any report page, click **Download PDF** (or the PDF icon in the report header).

The PDF downloads immediately and includes:
- All findings with evidence
- Security score and grade
- Executive summary
- Remediation recommendations
- OWASP and MITRE mappings
- Certificate and DNS details

**File name format:** `sentinelscan-report-{scan-id}.pdf`

---

## Sharing Reports

Reports can be shared publicly via a link without requiring the recipient to have an account.

1. On the report page, click **Share Report**
2. Set an expiry period (1 day, 7 days, or 30 days)
3. Copy the generated link

The share link is accessible without login and shows the full report. The link automatically expires after the chosen period.

---

## Scan History

Navigate to **History** in the sidebar to see all your past scans.

**Filters available:**
- Status (all, completed, failed, cancelled)
- Date range
- URL search

---

## Analytics

The **Analytics** page shows visual trends across all your scans:

- **Score over time** — line chart of security scores
- **Findings by severity** — stacked bar chart
- **Most common vulnerability categories** — pie chart
- **Average score per domain** — if you've scanned the same domain multiple times

---

## OWASP View

The **OWASP** page groups all findings from your reports by OWASP Top 10:2025 category. This helps you understand which OWASP risks are most prevalent across your assets.

---

## Compare Scans

The **Compare** page allows side-by-side comparison of two scan reports. Select two scans from the dropdowns to see:

- **New issues** — appeared in the second scan but not the first
- **Resolved issues** — present in the first scan, gone in the second
- **Unchanged** — present in both
- **Score delta** — how the score changed

---

## Notifications

In-app notifications appear in the sidebar notification bell. You receive notifications when:
- A scan completes successfully
- A scan fails (with error details)
- A scan is cancelled

Click any notification to navigate to the relevant report. Click **Mark all read** to clear the unread badge.

---

## Profile and Settings

### Profile

Navigate to **Profile** to:
- Update your display name
- Change your password
- View your account creation date

### Settings

Navigate to **Settings** to:
- Configure scanner preferences (stored in `scan_preferences` JSON field)
- View your usage (scans used this hour, active scans)

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
