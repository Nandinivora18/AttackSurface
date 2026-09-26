"""
AI Provider Abstraction — Ask Sentinel

Provides a clean provider interface so SentinelScan is not locked to a single
LLM vendor. The model name and all provider settings come exclusively from
app.config.Settings — never hardcoded in business logic.

Supported providers:
  - GeminiProvider  (AI_PROVIDER=gemini, default)
  - OpenAIProvider  (AI_PROVIDER=openai)

Security rules:
  - API keys are read from Settings only, never from request data
  - API keys are never logged at any log level
  - Secrets are never included in raised exceptions or error messages
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional

from app.config import settings  # module-level import so tests can patch app.ai.provider.settings

logger = logging.getLogger(__name__)

# Known placeholder values that indicate the key is not yet configured
_PLACEHOLDER_KEYS = frozenset({
    "YOUR_GEMINI_API_KEY",
    "your_gemini_api_key",
    "sk-proj-...",
    "changeme",
    "placeholder",
    "",
})


class AIProviderError(Exception):
    """Raised when the LLM provider returns an error or times out."""
    def __init__(self, message: str, status_code: int = 502, is_rate_limit: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.is_rate_limit = is_rate_limit


class AIProvider(ABC):
    """Abstract base class for LLM providers."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the configured model name (from settings, never hardcoded)."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return a human-readable provider identifier."""

    @abstractmethod
    async def chat(
        self,
        messages: list[dict],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Send messages to the LLM and return the assistant's reply as a string.

        Args:
            messages: List of {role, content} dicts (system + history + user)
            max_tokens: Override max output tokens (uses settings default if None)
            temperature: Override temperature (uses settings default if None)

        Returns:
            The assistant's response text.

        Raises:
            AIProviderError: On provider failure, timeout, or rate limit.
        """


class GeminiProvider(AIProvider):
    """Google Gemini API provider using official modern google-genai SDK.

    Configured via app.config.Settings:
      - AI_GEMINI_API_KEY (mandatory)
      - AI_GEMINI_MODEL (mandatory, e.g. 'gemini-1.5-flash')
      - AI_TEMPERATURE
      - AI_MAX_OUTPUT_TOKENS
      - AI_REQUEST_TIMEOUT_SECONDS

    The API key is never logged or included in exceptions.
    """

    def __init__(self, settings):
        """
        Args:
            settings: app.config.Settings instance.
        """
        api_key = getattr(settings, "AI_GEMINI_API_KEY", None)
        if not api_key or api_key.strip() in _PLACEHOLDER_KEYS:
            raise AIProviderError(
                "Gemini API key is not configured. Set AI_GEMINI_API_KEY in the environment.",
                status_code=503,
            )

        model = getattr(settings, "AI_GEMINI_MODEL", None)
        if not model or not model.strip():
            raise AIProviderError(
                "Gemini model is not configured. Set AI_GEMINI_MODEL in the environment.",
                status_code=503,
            )

        try:
            from google import genai
        except ImportError:
            raise AIProviderError(
                "google-genai package is not installed. Run: pip install google-genai",
                status_code=503,
            )

        self._client = genai.Client(api_key=api_key.strip())
        self._settings = settings

    @property
    def model_name(self) -> str:
        return self._settings.AI_GEMINI_MODEL

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def chat(
        self,
        messages: list[dict],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        try:
            from google.genai import types as genai_types
            from google.genai.errors import APIError as GenAIAPIError
        except ImportError:
            raise AIProviderError(
                "google-genai package is not installed. Run: pip install google-genai",
                status_code=503,
            )

        _max_tokens = max_tokens if max_tokens is not None else self._settings.AI_MAX_OUTPUT_TOKENS
        _temperature = temperature if temperature is not None else self._settings.AI_TEMPERATURE

        # Extract system messages into a unified system instruction
        system_parts = [
            m["content"]
            for m in messages
            if m.get("role") == "system" and m.get("content")
        ]
        system_instruction = "\n\n".join(system_parts) if system_parts else None

        # Build conversation contents for Gemini (roles: 'user' and 'model')
        contents = []
        last_role = None
        for m in messages:
            role = m.get("role")
            if role == "system":
                continue
            gemini_role = "model" if role == "assistant" else "user"
            text_content = m.get("content", "")
            # Ensure conversation begins with a user turn
            if not contents and gemini_role != "user":
                contents.append(
                    genai_types.Content(
                        role="user",
                        parts=[genai_types.Part.from_text(text="Explain the security context.")],
                    )
                )
                last_role = "user"
            # If adjacent same role, merge into previous turn
            if gemini_role == last_role and contents:
                if text_content:
                    contents[-1].parts.append(genai_types.Part.from_text(text="\n" + text_content))
                continue
            contents.append(
                genai_types.Content(
                    role=gemini_role,
                    parts=[genai_types.Part.from_text(text=text_content)],
                )
            )
            last_role = gemini_role

        if not contents:
            contents = [
                genai_types.Content(
                    role="user",
                    parts=[genai_types.Part.from_text(text="")],
                )
            ]

        config = genai_types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=_temperature,
            max_output_tokens=_max_tokens,
        )

        timeout_sec = float(self._settings.AI_REQUEST_TIMEOUT_SECONDS)

        try:
            model_candidates = [self._settings.AI_GEMINI_MODEL]
            for fallback in ["models/gemini-3.5-flash-lite", "models/gemini-3.7-flash"]:
                if fallback not in model_candidates:
                    model_candidates.append(fallback)

            response = None
            per_model_timeout = min(timeout_sec, 15.0) if len(model_candidates) > 1 else timeout_sec

            for attempt, candidate_model in enumerate(model_candidates, start=1):
                try:
                    response = await asyncio.wait_for(
                        self._client.aio.models.generate_content(
                            model=candidate_model,
                            contents=contents,
                            config=config,
                        ),
                        timeout=per_model_timeout,
                    )
                    break
                except Exception as loop_exc:
                    err_str = str(loop_exc)
                    err_code = getattr(loop_exc, "code", None)
                    is_transient_or_quota = (
                        isinstance(loop_exc, asyncio.TimeoutError)
                        or err_code in (429, 500, 502, 503, 504)
                        or "429" in err_str
                        or "503" in err_str
                        or "500" in err_str
                        or "RESOURCE_EXHAUSTED" in err_str
                        or "quota" in err_str.lower()
                        or "Service Unavailable" in err_str
                        or "ServerError" in type(loop_exc).__name__
                        or "overloaded" in err_str.lower()
                        or "temporarily unavailable" in err_str.lower()
                        or "timeout" in err_str.lower()
                    )
                    if is_transient_or_quota and attempt < len(model_candidates):
                        backoff = 1.0 * attempt
                        next_model = model_candidates[attempt]
                        logger.warning(
                            "Gemini chat: model %s error (attempt %d/%d): %s. Falling back to %s in %.1fs...",
                            candidate_model, attempt, len(model_candidates), err_str[:120], next_model, backoff,
                        )
                        await asyncio.sleep(backoff)
                        continue
                    raise
            return getattr(response, "text", "") or ""

        except asyncio.TimeoutError:
            raise AIProviderError(
                "The AI service took too long to respond. Please try again.",
                status_code=504,
            )
        except Exception as exc:
            from google.genai.errors import APIError as GenAIAPIError
            err_code = getattr(exc, "code", None)
            err_str = str(exc)

            if err_code == 429 or "RESOURCE_EXHAUSTED" in err_str or "quota" in err_str.lower():
                raise AIProviderError(
                    "The AI service is temporarily rate-limited. Please try again in a moment.",
                    status_code=429,
                    is_rate_limit=True,
                )
            if (
                err_code in (401, 403)
                or "API_KEY_INVALID" in err_str
                or "PERMISSION_DENIED" in err_str
                or "api key not valid" in err_str.lower()
            ):
                logger.warning("Gemini authentication failed — check AI_GEMINI_API_KEY configuration.")
                raise AIProviderError(
                    "The AI service is not properly configured. Please contact your administrator.",
                    status_code=503,
                )
            if err_code == 404 or "NOT_FOUND" in err_str or "is not found for API version" in err_str:
                logger.warning("Gemini model '%s' unavailable or not found.", self.model_name)
                raise AIProviderError(
                    f"Configured Gemini model '{self.model_name}' is not available.",
                    status_code=502,
                )

            logger.warning("Gemini API error (code=%s, type=%s)", err_code, type(exc).__name__)
            raise AIProviderError(
                f"The AI service returned an error ({type(exc).__name__}). Please try again.",
                status_code=502,
            )
        except AIProviderError:
            raise
        except Exception as exc:
            logger.warning("Unexpected Gemini provider error (type=%s)", type(exc).__name__)
            raise AIProviderError(
                "An unexpected error occurred while contacting the AI service.",
                status_code=502,
            )


class OpenAIProvider(AIProvider):
    """OpenAI Chat Completions provider.

    Model, API key, base URL, temperature, and token limits all come from
    app.config.Settings. The API key is never logged or included in exceptions.
    """

    def __init__(self, settings):
        """
        Args:
            settings: app.config.Settings instance. API key read here once.
        """
        api_key = getattr(settings, "AI_OPENAI_API_KEY", None)
        if not api_key or api_key.strip() in _PLACEHOLDER_KEYS:
            raise AIProviderError(
                "OpenAI API key is not configured. Set AI_OPENAI_API_KEY in the environment.",
                status_code=503,
            )

        model = getattr(settings, "AI_OPENAI_MODEL", None)
        if not model or not model.strip():
            raise AIProviderError(
                "OpenAI model is not configured. Set AI_OPENAI_MODEL in the environment.",
                status_code=503,
            )

        try:
            import openai
        except ImportError:
            raise AIProviderError(
                "openai package is not installed. Run: pip install openai>=1.40.0",
                status_code=503,
            )

        client_kwargs: dict = {
            "api_key": api_key.strip(),
            "timeout": float(settings.AI_REQUEST_TIMEOUT_SECONDS),
        }
        if settings.AI_OPENAI_BASE_URL:
            client_kwargs["base_url"] = settings.AI_OPENAI_BASE_URL

        self._client = openai.AsyncOpenAI(**client_kwargs)
        self._settings = settings

    @property
    def model_name(self) -> str:
        return self._settings.AI_OPENAI_MODEL

    @property
    def provider_name(self) -> str:
        return "openai"

    async def chat(
        self,
        messages: list[dict],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        import openai

        _max_tokens = max_tokens if max_tokens is not None else self._settings.AI_MAX_OUTPUT_TOKENS
        _temperature = temperature if temperature is not None else self._settings.AI_TEMPERATURE

        try:
            response = await self._client.chat.completions.create(
                model=self._settings.AI_OPENAI_MODEL,  # always from settings
                messages=messages,
                max_tokens=_max_tokens,
                temperature=_temperature,
            )
            return response.choices[0].message.content or ""

        except openai.RateLimitError:
            raise AIProviderError(
                "The AI service is temporarily rate-limited. Please try again in a moment.",
                status_code=429,
                is_rate_limit=True,
            )
        except openai.APITimeoutError:
            raise AIProviderError(
                "The AI service took too long to respond. Please try again.",
                status_code=504,
            )
        except openai.AuthenticationError:
            # Log at warning level, never log the key itself
            logger.warning("OpenAI authentication failed — check AI_OPENAI_API_KEY configuration.")
            raise AIProviderError(
                "The AI service is not properly configured. Please contact your administrator.",
                status_code=503,
            )
        except openai.APIError as exc:
            logger.warning("OpenAI API error (type=%s)", type(exc).__name__)
            raise AIProviderError(
                f"The AI service returned an error ({type(exc).__name__}). Please try again.",
                status_code=502,
            )
        except Exception as exc:
            logger.warning("Unexpected AI provider error (type=%s)", type(exc).__name__)
            raise AIProviderError(
                "An unexpected error occurred while contacting the AI service.",
                status_code=502,
            )


# ── Provider factory ─────────────────────────────────────────────────────────

_cached_provider: Optional[AIProvider] = None
_cached_provider_key: Optional[tuple] = None


def reset_ai_provider_cache() -> None:
    """Reset the cached AI provider instance. Used in tests and reloads."""
    global _cached_provider, _cached_provider_key
    _cached_provider = None
    _cached_provider_key = None


def get_ai_provider() -> Optional[AIProvider]:
    """
    Return the configured AI provider, or None if not configured.

    Reuses and caches the provider instance across requests to avoid
    re-instantiating the SDK client and connection pool on every message.
    Returns None (not raises) so callers can handle the unconfigured state
    gracefully without crashing the application.
    """
    provider_name = (settings.AI_PROVIDER or "").strip().lower()

    if not provider_name:
        return None

    cache_key = (
        id(settings),
        provider_name,
        getattr(settings, "AI_GEMINI_API_KEY", None),
        getattr(settings, "AI_GEMINI_MODEL", None),
        getattr(settings, "AI_OPENAI_API_KEY", None),
        getattr(settings, "AI_OPENAI_MODEL", None),
        getattr(settings, "AI_OPENAI_BASE_URL", None),
        getattr(settings, "AI_REQUEST_TIMEOUT_SECONDS", None),
    )

    global _cached_provider, _cached_provider_key
    if _cached_provider is not None and _cached_provider_key == cache_key:
        return _cached_provider

    provider: AIProvider
    if provider_name == "gemini":
        try:
            provider = GeminiProvider(settings)
        except AIProviderError:
            raise
        except Exception as exc:
            logger.error("Failed to initialize Gemini provider: %s", type(exc).__name__)
            raise AIProviderError(
                "Failed to initialize the Gemini AI provider. Check configuration.",
                status_code=503,
            )

    elif provider_name == "openai":
        try:
            provider = OpenAIProvider(settings)
        except AIProviderError:
            raise
        except Exception as exc:
            logger.error("Failed to initialize OpenAI provider: %s", type(exc).__name__)
            raise AIProviderError(
                "Failed to initialize the OpenAI AI provider. Check configuration.",
                status_code=503,
            )
    else:
        raise AIProviderError(
            f"Unknown AI provider '{provider_name}'. Supported: gemini, openai",
            status_code=503,
        )

    _cached_provider = provider
    _cached_provider_key = cache_key
    return provider

