"""
SentinelScan AI Assistant — Ask Sentinel

Provides evidence-grounded security intelligence rooted in actual scan data.
This package contains the provider abstraction, context builder, knowledge
base, system prompt, and per-user rate limiter.

Architecture:
  app.routers.ai     ← FastAPI router (auth, rate-limit, orchestration)
  app.ai.provider    ← LLM provider abstraction (OpenAI + future providers)
  app.ai.context     ← Scan/finding context builder (ownership-enforced)
  app.ai.sanitize    ← Context-specific secret sanitization before LLM
  app.ai.knowledge   ← SentinelScan knowledge base (structured, no vector DB)
  app.ai.system_prompt ← Grounding system prompt
  app.ai.rate_limiter  ← Per-user Redis rate limiter
"""
