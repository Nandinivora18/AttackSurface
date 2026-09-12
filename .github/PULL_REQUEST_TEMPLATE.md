## What changed?

<!-- Provide a clear, high-level summary of the changes introduced in this pull request. -->

## Why?

<!-- Explain the motivation, problem solved, or feature enabled by this pull request. -->

## Security impact

<!-- Describe any potential security implications, attack surface changes, authentication alterations, or data exposure risks. -->

## Tests performed

- [ ] Backend tests (`.venv\Scripts\python.exe -m pytest tests/ -v`)
- [ ] TypeScript typecheck (`npx tsc --noEmit`)
- [ ] Production build (`npm run build`)
- [ ] Security checks (`git diff --check` and secret audit)

## Checklist

- [ ] No secrets or private credentials committed
- [ ] No `.env` or `.env.local` files committed
- [ ] No unrelated files or temporary artifacts modified
- [ ] Documentation updated (`docs/` and `README.md` if applicable)
- [ ] Security implications reviewed
