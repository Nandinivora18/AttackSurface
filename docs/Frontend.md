# Frontend Architecture

## Overview

The SentinelScan frontend is a **Next.js 14 application** using the App Router, TypeScript, and Tailwind CSS. It communicates with the FastAPI backend via an Axios-based API client and receives real-time scan updates via Server-Sent Events (SSE).

---

## Folder Structure

```
frontend/src/
├── app/                          # Next.js App Router (24 pages)
│   ├── layout.tsx                # Root HTML layout with permanent dark theme & toaster
│   ├── page.tsx                  # Landing page (marketing & live simulator)
│   ├── globals.css               # Design tokens (Obsidian Black + Metallic Gold) & Tailwind
│   │
│   ├── (auth)/                   # Authentication route group
│   │   ├── login/
│   │   ├── signup/
│   │   ├── forgot-password/
│   │   ├── reset-password/
│   │   └── verify-email/
│   │
│   ├── (dashboard)/              # Protected route group
│   │   ├── layout.tsx            # Dashboard shell (sidebar + header)
│   │   ├── dashboard/            # Home dashboard & posture metrics
│   │   ├── scan/                 # New scan & live progress
│   │   ├── reports/              # Report inventory
│   │   │   └── [id]/             # Report overview & tabs
│   │   │       ├── headers/      # Security headers tab
│   │   │       ├── ssl/          # SSL/TLS certificate tab
│   │   │       ├── dns/          # DNS security records tab
│   │   │       └── tech/         # Technology & CVE tab
│   │   ├── findings/             # Finding detail & remediation
│   │   │   └── [id]/             # Finding deep-dive workspace
│   │   ├── history/              # Scan history table & filters
│   │   ├── assets/               # Monitored perimeter assets
│   │   │   └── [id]/             # Asset detail & score history
│   │   ├── profile/              # User profile & sessions
│   │   ├── settings/             # Theme & notification settings
│   │   └── admin/                # Admin center & user management
│   │       └── health/           # System health & telemetry
│   │
│   ├── auth/                     # OAuth callback handler
│   │   └── callback/
│
├── components/                   # Reusable React components
│   ├── ai/                       # Ask Sentinel panel, button, message bubble, quick actions
│   ├── dashboard/                # Dashboard widgets (SentinelDeltaWidget, RecentScans)
│   ├── layout/                   # Sidebar, DashboardHeader, Navbar
│   ├── reports/                  # Report sub-nav
│   ├── shared/                   # SeverityBadge, GlassCard, CommandPalette
│   └── ui/                       # Base design system (Button, Badge, Input, SectionCard)
│
├── lib/                          # API client (Axios), utilities, aiApi, date formatting
├── types/                        # TypeScript interfaces (including AI types)
└── tailwind.config.js
```

---

## Pages

### Landing Page (`app/page.tsx`)

The public homepage featuring:
- Hero section with live interactive scan simulator
- Key value propositions and security capability cards
- Technology stack overview
- 3-step security process walkthrough
- Pricing tiers and customer testimonials
- Call-to-action buttons (Start Free Scan / Sign In)

### Dashboard (`(dashboard)/dashboard/`)

The primary executive control center after login:
- **Security Score Ring** — animated circular gauge of overall attack surface posture
- **Finding Statistics** — Critical, High, Medium, and Low counts
- **30-Day Posture Trend** — historical posture line chart (shows clear helper state when < 2 scans)
- **Quick Scan Widget** — one-click scan launcher
- **Recent Scans List** — recent assessments with direct report navigation

### Scan Page (`(dashboard)/scan/`)

The interactive scan creation and real-time monitoring workspace:
- **Target URL input** — format validation with instant target chips
- **Scan Profiles** — Quick, Standard, and Custom configuration
- **Scan Coverage Vector Card** — details the 7 inspection vectors
- **Live Progress Timeline** — 8-stage progress bar powered by ticket-authenticated SSE
- **Cooperative Cancellation** — abort running jobs cleanly

### Reports & Sub-Pages (`(dashboard)/reports/`)

- **List view (`/reports`):** Searchable, filterable list of all generated security reports with export shortcuts.
- **Overview (`/reports/[id]`):** Executive summary, risk score, grade gauge, assessment methodology, and finding triage list.
- **Security Headers (`/reports/[id]/headers`):** Detailed analysis of HSTS, CSP, XFO, CORS, and server banners.
- **SSL / TLS (`/reports/[id]/ssl`):** Certificate validity, issuer, cipher suite strength, and protocol versions.
- **DNS Security (`/reports/[id]/dns`):** SPF, DMARC, DNSSEC, MX records, and mail security posture.
- **Technology & CVE (`/reports/[id]/tech`):** Detected tech stack, semver versions, and NIST NVD CVE correlations.

### Finding Detail (`(dashboard)/findings/[id]`)

Dedicated finding workspace with:
- Severity badge, CVSS v3 score gauge, and verification status
- Multi-tab breakdown: Problem & Impact, Technical Root Cause & Evidence, Step-by-Step Fix Instructions with Nginx/Apache code snippets, Best Practices & Official Documentation
- OWASP Top 10, CWE, and MITRE ATT&CK taxonomy tags
- Workflow status updater (`open`, `in_progress`, `resolved`, `false_positive`)

### History (`(dashboard)/history/`)

Audit log of all past security assessments with search, date sorting, and status filtering.

### Profile (`(dashboard)/profile/`)

User account management:
- Identity card with user initials badge, display name, and verified email
- Google OAuth connection indicator
- Password reset and update workflows
- Active session viewer with remote session termination

### Settings (`(dashboard)/settings/`)

Application preferences:
- Dark-only theme indicator (no theme switching — SentinelScan uses permanent dark mode)
- Email notification preferences (Scan completion emails, critical alerts)

### Admin Center (`(dashboard)/admin/` & `health/`)

Restricted to users with `admin` role:
- User directory and role management
- Real-time system health, database readiness, Redis cache status, and worker telemetry

> **Note:** The legacy public Share Page (`app/share/[token]/`) and Assets (`(dashboard)/assets/`) routes were removed alongside the retired `share_links` and `assets` database tables (migration `7340c9ab6be5`). Reports are private to their owner.

---

## Components

### AI Components (`components/ai/`)

**`AskSentinelPanel.tsx`**
- Slide-in AI assistant panel, globally mounted in the dashboard layout
- Displays conversation history with role-differentiated message bubbles
- Supports scan context, finding context, and general (platform knowledge) mode
- Quick actions toolbar with pre-built prompt shortcuts
- Regenerate last response, clear conversation controls

**`AskSentinelButton.tsx`**
- Persistent floating trigger button for opening the Ask Sentinel panel
- Always available from any dashboard page

**`FindingAskButton.tsx`**
- Context-specific Ask Sentinel entry point on finding detail pages
- Pre-loads finding ID and title into the panel context

**`QuickActions.tsx`**
- Grid of pre-built prompt chips (summarize findings, explain severity, remediation plan, etc.)
- Context-adaptive: different actions shown for scan vs. finding vs. general context

**`MessageBubble.tsx`**
- Renders individual AI messages with markdown, source citations, and error states

### Layout Components

**`Sidebar.tsx`**
- Fixed left navigation with collapsible sections
- Active page highlighting via `usePathname()`
- Notification badge on notification icon
- User avatar + name display
- Role-conditional admin link

**`DashboardLayout.tsx`**
- Top-level wrapper for all dashboard pages
- Authentication guard: redirects to `/login` if no valid token
- Provides `NotificationProvider` and `AuthContext`

### Scanner Components

**`ScanForm.tsx`**
- Controlled URL input with basic validation
- `POST /api/scans` submission with loading state
- Redirects to scan progress view on success

**`ScanProgress.tsx`**
- Connects to SSE endpoint via `useEventSource` hook
- Renders animated progress bar
- Displays stage timeline (completed, active, pending stages)
- On `status=completed`, navigates to report
- On `status=failed`, shows error message

### Report Components

**`ReportCard.tsx`**
- Summary card with score ring, grade badge, key metrics
- Used in scan list and dashboard

**`FindingsTable.tsx`**
- Sortable, filterable table of findings
- Severity filter chips
- Category filter dropdown
- Search by title or description
- Expandable rows with full finding detail

**`ScoreRing.tsx`**
- SVG-based animated circular progress
- Color-coded by grade (green/yellow/orange/red)

**`SeverityBadge.tsx`**
- Color-coded pill badge for finding severity
- Consistent visual language across the application

### Shared Components

**`GlassCard.tsx`**
- Base card component with glassmorphism styling
- Used throughout dashboard and reports

**`Toast.tsx`**
- In-app notification system
- `success`, `error`, `warning`, `info` variants
- Auto-dismiss after 5 seconds

---

## Hooks

### `useAuth()`

Returns the current user from `AuthContext`. Provides:
- `user` — current user object (or `null`)
- `login(email, password)` — calls `/api/auth/login`, stores tokens
- `logout()` — calls `/api/auth/logout`, clears tokens
- `refreshToken()` — calls `/api/auth/refresh`
- `isLoading` — authentication state loading

### `useEventSource(url)`

Custom hook wrapping the browser's `EventSource` API:
- Opens SSE connection
- Returns `{ data, error, readyState }`
- Cleans up on unmount
- Handles reconnection

### `useNotifications()`

Polls `/api/notifications` on a 30-second interval. Returns:
- `notifications` — list
- `unreadCount` — integer
- `markRead(id)` — marks one as read
- `markAllRead()` — marks all as read

---

## AI Assistant & Circle to Sentinel Components

SentinelScan includes an integrated evidence-grounded AI intelligence suite in `src/components/ai/`:

### `AskSentinelButton.tsx`
- Floating and dashboard-embedded trigger for Sentinel Intelligence.
- Displays active scan or finding context indicators and provides keyboard shortcut bindings (`Cmd+K` / `Ctrl+K`).
- Triggers the slide-over AI assistant panel with current page context.

### `AskSentinelPanel.tsx`
- Persistent slide-over modal/drawer interface for interactive security conversations.
- Features multi-turn conversational history (up to 10 turns), message streaming/loading state, rate limit remaining indicators, and direct links to finding records.
- Provides double-submit protection, retry actions on error, and graceful timeout UX.
- Renders answers via GitHub-flavored Markdown with syntax-highlighted code/config blocks.

### `CircleToSentinel.tsx`
- Interactive visual viewport selection overlay inspired by visual search, purpose-built for the SentinelScan security UI.
- **Activation:** Triggered via global keyboard shortcut `Ctrl+Shift+S` (Windows/Linux) or `Cmd+Shift+S` (macOS), or via the visual inspect button.
- **Pointer Events:** Universal support for mouse, touch, and stylus drag interactions.
- **Selection Mechanics:** High-contrast marching-ants bounding box with corner grab handles, semi-transparent backdrop overlay, and live coordinate tracking.
- **Safety & Filtering:** Rejects micro-selections (< 20px width/height) to prevent accidental clicks; supports `Escape` key cancellation.
- **Context Extraction:** Automatically captures the bounding box coordinates, renders the visual region to a client-side canvas as a base64 JPEG (`image/jpeg` at 0.85 quality), extracts text from DOM nodes within the bounding box, and attaches existing scan/finding metadata.
- **Automatic Explanation Flow:** Automatically opens the `AskSentinelPanel` and issues `POST /api/ai/visual-chat` with an internal explanation intent (`"Analyzing selected area..."`), rendering an evidence-grounded explanation without requiring manual user typing or inserting fake user messages.

### `FindingAskButton.tsx`
- Contextual action button rendered on finding cards and finding detail pages.
- Instantly launches Ask Sentinel pre-grounded with the specific finding's evidence, OWASP/CWE category, CVSS score, and remediation steps.

### `MessageBubble.tsx`
- Markdown-enabled message component supporting formatted headings, lists, badges (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[INFO]`), copy buttons, and source citation badges (`"Circle to Sentinel (Visual Context)"`, `"Live Scan Evidence"`).

### `QuickActions.tsx`
- Context-sensitive prompt chips (e.g., *"Explain this score"*, *"How do I fix the highest risk finding?"*, *"Summarize TLS posture"*) allowing instant one-click analysis.

---

## State Management

SentinelScan uses **Zustand** for global client state (not Redux). Store modules are in `src/store/`:

**`useAuthStore`** (`store/index.ts`)
- Current user object and authentication status
- login / logout / fetchMe / setUser actions
- Persisted to localStorage (`sentinel-auth`)

**`useScanStore`** (`store/index.ts`)
- Recent scans, current scan, current report
- Scan progress (progress %, stage, message)

**`useUIStore`** (`store/index.ts`)
- Sidebar open/closed state
- Persisted to localStorage (`sentinel-ui-storage`)

**`useAIStore`** (`store/aiStore.ts`)
- Ask Sentinel panel open/closed state
- Current context (scan ID, finding ID, context type)
- Conversation messages history
- sendMessage, clearConversation, regenerateLastResponse actions
- Duplicate-request guard (`_isSubmitting` flag)

**`useNotificationStore`** (`store/index.ts`)
- Notification list, unread count
- fetchNotifications, markAsRead, markAllAsRead, deleteNotification

**Local state** (via `useState` and `useReducer`) handles:
- Form inputs
- Filter/sort state
- Pagination
- Modal open/close

---

## API Communication

All API calls go through `src/lib/api.ts`, which creates an Axios instance with:

```typescript
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  timeout: 30000,
});

// Request interceptor: attach Bearer token
api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Response interceptor: auto-refresh on 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      await refreshAccessToken();
      return api(error.config);  // retry with new token
    }
    return Promise.reject(error);
  }
);
```

---

## Authentication Flow (Frontend)

```mermaid
flowchart TD
    A[Page load] --> B{Token in storage?}
    B -- No --> C[Redirect to /login]
    B -- Yes --> D[Decode token expiry]
    D -- Expired --> E[POST /api/auth/refresh]
    E -- Success --> F[Store new access_token]
    E -- Failed --> C
    D -- Valid --> G[Continue to page]
    F --> G
    G --> H[Auth header attached to all requests]
```

---

## Error Handling

**API errors:** Axios interceptors catch all non-2xx responses. `422` validation errors surface field-level messages in forms. `500` errors show a generic toast.

**SSE errors:** The `useEventSource` hook sets `error` state on `EventSource.onerror`. The scan progress page shows a "Connection interrupted" message and offers a Retry button.

**Render errors:** Next.js `error.tsx` boundaries catch unexpected render exceptions.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | ✅ | Backend API base URL |
| `NEXT_PUBLIC_GOOGLE_CLIENT_ID` | Optional | Google OAuth client ID for login button |

---

## Key Design Decisions

1. **App Router (not Pages Router)** — enables layout-level server components and eliminates wrapper boilerplate
2. **Zustand for client state** — lightweight, hook-based stores for auth, UI, scans, and AI assistant; avoids heavy Redux boilerplate
3. **SSE over WebSockets** — simpler server-side implementation; uni-directional updates are sufficient for scan progress
4. **Axios over fetch** — interceptors enable token refresh without per-call boilerplate
5. **Tailwind CSS** — utility-first CSS enables rapid iteration without CSS file proliferation
