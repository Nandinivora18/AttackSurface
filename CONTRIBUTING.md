# Contributing to SentinelScan

Thank you for contributing to SentinelScan! This guide explains our development workflow, branch naming conventions, testing standards, and collaboration rules.

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Nandinivora18/SentinalScan.git
cd SentinalScan
```

### 2. Set Up Virtual Environment (Backend)
```bash
cd backend
python -m venv .venv

# Activate virtual environment:
.venv\Scripts\Activate.ps1       # Windows (PowerShell)
# .venv\Scripts\activate.bat     # Windows (Command Prompt)
# source .venv/bin/activate      # macOS/Linux

# Install all dependencies (runtime + dev/test):
pip install -r requirements.txt -r requirements-dev.txt

# Configure local development environment
cp .env.example .env
# Edit backend/.env — set a development SECRET_KEY
```

### 3. Set Up Frontend
```bash
cd ../frontend
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
```

---

## 🌿 Collaboration & Git Workflow

### Golden Rules
1. **Never commit `.env` or credentials** — all secrets must stay local.
2. **Never force-push to `main`** — keep the `main` branch stable, tested, and deployable at all times.
3. **Pull `main` before branching** — always base your branch on the latest `origin/main`.
4. **Use Pull Requests for shared changes** — even for pairs, open a PR for code review and verification before merging.

### Branch Naming Conventions
Use descriptive prefixes for all branches:

- `feature/<name>` — New capabilities, detectors, or UI components (e.g. `feature/jwt-rotation`)
- `fix/<name>` — Bug fixes and false-positive suppression (e.g. `fix/server-banner-regex`)
- `security/<name>` — Security controls, SSRF protections, auth hardening (e.g. `security/ssrf-rebind`)
- `docs/<name>` — Documentation updates and guides (e.g. `docs/api-examples`)
- `test/<name>` — Test suite improvements or new fixtures (e.g. `test/oauth-mocks`)

### Standard Workflow
```bash
# 1. Ensure main is up to date
git checkout main
git pull origin main

# 2. Create your feature branch
git checkout -b feature/my-feature-name

# 3. Make and verify changes
# Run backend tests
cd backend && .venv\Scripts\python.exe -m pytest tests/ -q

# Run frontend type check & build
cd ../frontend && npx tsc --noEmit && npm run build

# 4. Commit with Conventional Commits message
git commit -m "feat(scanner): add Permissions-Policy header detector"

# 5. Push to GitHub
git push -u origin feature/my-feature-name

# 6. Open a Pull Request against main on GitHub
```

---

## 🧪 Testing Standards

Every PR that introduces or modifies backend logic must include test coverage:

```bash
cd backend

# Run the complete test suite
.venv\Scripts\python.exe -m pytest tests/ -v

# Run a specific test file
.venv\Scripts\python.exe -m pytest tests/test_accuracy.py -v
```

### Adding New Detectors
See [docs/DeveloperGuide.md](docs/DeveloperGuide.md) for the detector registration checklist:
- Register in `app/scanner/metadata.py` (`DETECTOR_REGISTRY`).
- Every detector **must** include a false-positive regression test showing what should *not* be flagged.
- Include structured raw evidence in findings.
- Severity and confidence ratings must follow the calibrated scoring guide.

---

## 📝 Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional detailed description>
```

**Types:**
- `feat` — New feature, detector, or page
- `fix` — Bug fix or false-positive regression correction
- `security` — Security hardening or vulnerability remediation
- `test` — Adding or modifying tests
- `docs` — Documentation updates
- `refactor` — Code change without functional or security change
- `chore` — Dependencies, build configuration, or repository maintenance

---

## 🛡️ Security Vulnerabilities

Please **do not** report security vulnerabilities via public GitHub issues. Follow our [Security Policy](SECURITY.md) and email `security@sentinelscan.io`.

---

## 📄 License & Code of Conduct

By contributing to SentinelScan, you agree that your contributions will be licensed under the project's [MIT License](LICENSE) and that you abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
